# Google Threat Intelligence - DTM Alerts

This integration allows the creation of incidents based on DTM Alerts from Google Threat Intelligence.

## Configure Google Threat Intelligence - DTM Alerts in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | See [Acquiring your API key](#acquiring-your-api-key) | True |
| Fetch incidents |  | False |
| Max Fetch | Maximum number of Alerts to fetch each time. Maximum value is 25. | False |
| First Fetch Time | The date or relative timestamp from which to begin fetching Alerts.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2025, 01 May 2025 04:45:33, 2025-05-17T14:05:44Z.<br/> | False |
| Mirroring Direction | The mirroring direction in which to mirror the details. You can mirror "Outgoing" \(from XSOAR to GTI\) direction for DTM Alerts. | False |
| Alert Type | Fetch Alerts by the specified alert types. | False |
| Alert Monitor ID | Fetch Alerts by the specified monitor IDs. | False |
| Alert Status | Fetch Alerts by the specified status. | False |
| Alert Severity | Fetch Alerts by the specified severity. | False |
| Alert Tags | Fetch Alerts by the specified tags. | False |
| Alert Match Value | Fetch Alerts by specified match value. | False |
| Alert mscore | Fetch Alerts with mscore greater than or equal to the given value.<br/><br/>Note: Valid range is 0 to 100. | False |
| Alert Search | Search Alerts and triggering documents using a Lucene query with text values joined by AND/OR. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

### Acquiring your API key

Your API key can be found in your GoogleThreatIntelligence account user menu, clicking on your avatar:

![How to get api key in GoogleThreatIntelligence](../../doc_files/Google_Threat_intelligence_API_key.png)

Your API key carries all your privileges, so keep it secure and don't share it with anyone.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gti-dtm-alert-list

***
Search the DTM Alerts with provided filter arguments.

#### Base Command

`gti-dtm-alert-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | Start time of the time range to list alerts.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2025, 01 Mar 2025 04:45:33, 2025-04-17T14:05:44Z. | Optional |
| end_time | End time of the time range to list alerts.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2025, 01 Mar 2025 04:45:33, 2025-04-17T14:05:44Z. | Optional |
| order | Filter alerts by the provided sort order. Possible values are: Asc, Desc. Default is Desc. | Optional |
| sort | Filter alerts by the provided sort field. Possible values are: Created At, Updated At, Monitor ID, ID. Default is Created At. | Optional |
| page_size | Specify the desired page size for the request. Maximum value is 25. Default is 10. | Optional |
| monitor_id | Filter alerts by monitor IDs. Supports comma-separated values. | Optional |
| alert_type | Filters alerts by their alert type. Supports comma-separated values. Possible values are: Compromised Credentials, Domain Discovery, Forum Post, Message, Paste, Shop Listing, Tweet, Web Content. | Optional |
| tags | Filter alerts by tags value. Supports comma-separated values. | Optional |
| status | Filter alerts by the provided status. Supports comma-separated values. Possible values are: New, Read, In Progress, Escalated, Closed, No Action Required, Duplicate, Not Relevant, Tracked External. | Optional |
| severity | Filter alerts by severity. Supports comma-separated values. Possible values are: Low, Medium, High. | Optional |
| mscore_gte | Filter alerts with mscore greater than or equal to the given value.<br/><br/>Note: Valid range is 0 to 100. | Optional |
| include_more_details | If yes, doc, labels, and topics are returned in the context data. Possible values are: Yes, No. Default is Yes. | Optional |
| include_monitor_name | If yes, then the monitor's name that created the alert is returned in the alert response body. Possible values are: Yes, No. Default is No. | Optional |
| has_analysis | If yes, then only alerts that have analysis are returned. An alert has analysis if it has either analysis text or analysis file attachments. Possible values are: Yes, No. | Optional |
| search | Filter alert and triggering document contents using a simple Lucene query string with one or more text values separated by AND or OR. | Optional |
| match_value | Filter alerts by the given match value. Supports comma-separated values. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleThreatIntelligenceDTMAlerts.Alerts.id | String | Unique identifier for the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.monitor_id | String | Identifier of the monitoring source that generated the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.__id | String | Unique document ID associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.__type | String | Type of document associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.body | String | Full content or message body of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.channel_id | String | ID of the channel where the alert was observed. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.channel_info.description | String | Description of the channel where the alert was detected. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.channel_url | String | URL of the detected channel. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.invite_url | String | Invite link of the detected channel, if available. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.messenger.id | String | Identifier of the messenger platform linked to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.messenger.name | String | Name of the messenger platform. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.name | String | Name of the channel where the content was found. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.ingested | Date | Date and time when the document was ingested into the system. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.message_id | String | Identifier of the specific message triggering the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.messenger.id | String | Messenger platform ID associated with the message. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.messenger.name | String | Name of the messenger platform associated with the message. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.avatar_file.hashes.sha256 | String | SHA-256 hash of the sender's avatar file. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.avatar_file.mime_type | String | MIME type of the sender's avatar file. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.identity.first_name | String | First name of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.identity.last_name | String | Last name of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.identity.name | String | Full name of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.telegram.name | String | Telegram username of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.telegram.user_id | Number | Telegram user ID of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.source | String | Source of the document or content triggering the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.timestamp | Date | Timestamp when the message or document was created. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.id | String | Unique identifier of the label assigned to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.classifier | String | Classifier name used for label assignment. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.version | String | Version of the classifier or labeling process. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.label | String | Name of the label assigned to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.confidence | Number | Confidence score of the assigned label. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.element_path | String | Path of the element where the label was applied. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.id | String | Unique identifier of the extracted topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.type | String | Type of the extracted topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.value | String | Value of the extracted topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.extractor | String | Name of the topic extraction tool. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.extractor_version | String | Version of the topic extractor used. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.entity_locations.element_path | String | Path of the element where the entity was detected. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.entity_locations.offsets | Number | Character offsets of the detected entity in the document. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topic_matches.topic_id | String | Identifier of the matched topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topic_matches.value | String | Matched value for the topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.label_matches | List | List of labels matched for the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc_matches.match_path | String | Path within the document where a match occurred. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc_matches.locations.offsets | Number | Offset positions of the document match. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc_matches.locations.value | String | Value of the matched document content. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.tags | List | Tags associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.created_at | Date | Date and time when the alert was created. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.updated_at | Date | Date and time when the alert was last updated. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels_url | String | URL to fetch labels associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics_url | String | URL to fetch topics associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc_url | String | URL of the original document related to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.status | String | Current status of the alert \(e.g., open, closed, triaged\). |
| GoogleThreatIntelligenceDTMAlerts.Alerts.alert_type | String | Type or category of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.alert_summary | String | Summary of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.title | String | Title of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.email_sent_at | String | Timestamp when the alert email was sent. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.indicator_mscore | Number | Malicious score of the indicator related to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.severity | String | Severity level of the alert \(e.g., low, medium, high\). |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence | Number | Confidence score of the alert detection. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.aggregated_under_id | String | ID under which the alert has been aggregated. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.monitor_name | String | Name of the monitoring source that generated the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.analysis | String | Analysis report or details associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.has_analysis | Boolean | Indicates whether the alert has an associated analysis. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.ai_doc_summary | String | AI-generated summary of the document related to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.similarity_score | Number | Similarity score between this alert and related alerts. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.severity_reasoning.rule | String | Rule used to determine the severity of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.version | String | Version of the confidence reasoning model. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.response_count | Number | Number of responses contributing to confidence reasoning. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.malicious_count | Number | Number of malicious detections contributing to confidence. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.benign_count | Number | Number of benign detections contributing to confidence. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.confidence_count | Number | Total number of samples considered for confidence calculation. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.explanation | String | Explanation behind the confidence score. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.ignore | Boolean | Indicates if the alert should be ignored. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.monitor_version | Number | Version of the monitoring source generating the alert. |

#### Command example

```!gti-dtm-alert-list alert_type=Message include_monitor_name=Yes include_more_details=Yes mscore_gte=11 order=Desc page_size=2 search=social severity=Low sort="Created At" tags=attempt```

#### Context Example

```json
{
    "GoogleThreatIntelligenceDTMAlerts": {
        "Alerts": [
            {
                "aggregated_under_id": "dummyaggregated_id_01",
                "ai_doc_summary": "This message advertises a service that provides fraudulent Google verification badges for any account. \n",
                "alert_summary": "Google verification badges for any account of the gmail and cloud.",
                "alert_type": "Message",
                "confidence": 0.20271267571752816,
                "confidence_reasoning": {
                    "benign_count": 0,
                    "malicious_count": 0,
                    "response_count": 0,
                    "version": ""
                },
                "created_at": "2025-05-21T11:28:02.646Z",
                "doc": {
                    "__id": "dummy_id_01",
                    "__type": "message",
                    "body": "dummy body for DTM Alerts",
                    "channel": {
                        "channel_id": "channeldummy",
                        "channel_info": {
                            "description": "Surge Market"
                        },
                        "channel_url": "dummyurl",
                        "invite_url": "dummyurl",
                        "messenger": {
                            "id": "Googlechat",
                            "name": "Googlechat"
                        },
                        "name": "social"
                    },
                    "ingested": "2025-05-21T11:27:45Z",
                    "message_id": "dummymessageid01",
                    "messenger": {
                        "id": "Googlechat",
                        "name": "Googlechat"
                    },
                    "sender": {
                        "identity": {
                            "first_name": "Crome Bot",
                            "name": "Crome Bot "
                        },
                        "googlechat": {
                            "name": "gmail",
                            "user_id": 220903062
                        }
                    },
                    "source": "googlw",
                    "timestamp": "2025-05-21T11:27:42Z"
                },
                "doc_matches": [
                    {
                        "locations": [
                            {
                                "offsets": [
                                    688,
                                    692
                                ],
                                "value": "full"
                            },
                            {
                                "offsets": [
                                    693,
                                    699
                                ],
                                "value": "access"
                            }
                        ],
                        "match_path": "body"
                    }
                ],
                "doc_url": "https://www.virustotal.com/v4/dtm/docs/message/dummydocurl01",
                "email_sent_at": "",
                "has_analysis": false,
                "id": "dummy_0000",
                "ignore": false,
                "indicator_mscore": 11,
                "tags": ["attempt","Test"],
                "labels": [
                    {
                        "classifier": "classifier-content",
                        "confidence": 100,
                        "element_path": "body",
                        "id": "dummy_label_id",
                        "label": "prose",
                        "version": "dummy_version"
                    }
                ],
                "labels_url": "https://www.virustotal.com/v4/dtm/docs/message/dummydocurl01/labels",
                "monitor_id": "dummy_monitor_id",
                "monitor_name": "Initial Access Broker",
                "monitor_version": 1,
                "severity": "low",
                "severity_reasoning": {
                    "rule": ""
                },
                "similarity_score": 0.9906103,
                "status": "read",
                "title": "Found topic \"google\" posted by actor \"sevenbump\" on channel \"social\"",
                "topic_matches": [
                    {
                        "offsets": [
                            0,
                            4
                        ],
                        "term": "google",
                        "topic_id": "dummy_topicid_01",
                        "value": "google"
                    },
                    {
                        "topic_id": "dummy_topicid_02",
                        "value": "message"
                    }
                ],
                "topics": [
                    {
                        "confidence": 99,
                        "entity_locations": [
                            {
                                "element_path": "body",
                                "offsets": [
                                    488,
                                    491
                                ]
                            }
                        ],
                        "extractor": "analysis of the message",
                        "extractor_version": "4-0-2",
                        "id": "dummy_topicid_01",
                        "type": "organization",
                        "value": "social"
                    },
                    {
                        "confidence": 94,
                        "entity_locations": [
                            {
                                "element_path": "body",
                                "offsets": [
                                    701,
                                    704
                                ]
                            }
                        ],
                        "extractor": "analysis-pipeline",
                        "extractor_version": "4-0-2",
                        "id": "dummy_topicid_02",
                        "type": "product",
                        "value": "social"
                    }
                ],
                "topics_url": "https://www.virustotal.com/v4/dtm/docs/message/dummydocurl02/topics",
                "updated_at": "2025-05-22T07:09:51.257Z"
            },
            {
                "aggregated_under_id": "dummy_aggregated_under_id_02",
                "ai_doc_summary": "This message advertises a service that offers unauthorized google account.\n",
                "alert_summary": "Google account verification service cromeam Stand out your way use any name any username any profile pic or none at all.",
                "alert_type": "Message",
                "confidence": 0.20271267571752816,
                "confidence_reasoning": {
                    "benign_count": 0,
                    "malicious_count": 0,
                    "response_count": 0,
                    "version": ""
                },
                "created_at": "2025-05-21T10:19:04.241Z",
                "doc": {
                    "__id": "dummy_doc_id_02",
                    "__type": "message",
                    "body": "this is body of message",
                    "channel": {
                        "channel_id": "-1001097206146",
                        "channel_info": {
                            "description": "Surge Market"
                        },
                        "channel_url": "https://dummyurl.com",
                        "invite_url": "https://dummyurl.com",
                        "messenger": {
                            "id": "googlechat",
                            "name": "Googlechat"
                        },
                        "name": "social"
                    },
                    "ingested": "2025-05-21T10:19:00Z",
                    "message_id": "dummy_message_id_02",
                    "messenger": {
                        "id": "googlechat",
                        "name": "Googlechat"
                    },
                    "sender": {
                        "identity": {
                            "first_name": "Crome Bot",
                            "name": "Crome Bot "
                        },
                        "telegram": {
                            "name": "sevenbump",
                            "user_id": 220903062
                        }
                    },
                    "source": "google",
                    "timestamp": "2025-05-21T10:18:55Z"
                },
                "doc_matches": [
                    {
                        "locations": [
                            {
                                "offsets": [
                                    688,
                                    692
                                ],
                                "value": "full"
                            },
                            {
                                "offsets": [
                                    693,
                                    699
                                ],
                                "value": "access"
                            }
                        ],
                        "match_path": "body"
                    }
                ],
                "doc_url": "https://www.virustotal.com/v4/dtm/docs/message/dummydocurl03",
                "email_sent_at": "",
                "has_analysis": false,
                "id": "dummy_0001",
                "ignore": false,
                "indicator_mscore": 11,
                "tags": ["attempt"],
                "labels": [
                    {
                        "classifier": "classifier-content",
                        "confidence": 100,
                        "element_path": "body",
                        "id": "dummyid03",
                        "label": "prose",
                        "version": "dummyversion03"
                    }
                ],
                "labels_url": "https://www.virustotal.com/v4/dtm/docs/message/dummydocurl03/labels",
                "monitor_id": "dummy_monitor_id",
                "monitor_name": "Initial Access Broker",
                "monitor_version": 1,
                "severity": "low",
                "severity_reasoning": {
                    "rule": ""
                },
                "similarity_score": 0.9906103,
                "status": "read",
                "title": "Found topic \"Google\" posted by actor \"sevenbump\" on Google channel \"social\"",
                "topic_matches": [
                    {
                        "offsets": [
                            0,
                            4
                        ],
                        "term": "dummyterm03",
                        "topic_id": "dummy_topic_01",
                        "value": "dummyvalue_03"
                    },
                    {
                        "topic_id": "dummay_topic_02",
                        "value": "message"
                    }
                ],
                "topics": [
                    {
                        "entity_locations": [
                            {
                                "element_path": "channel.name",
                                "offsets": [
                                    0,
                                    17
                                ]
                            }
                        ],
                        "extractor": "dtm-ma",
                        "extractor_version": "1.0.595",
                        "id": "dummy_topic_01",
                        "type": "name",
                        "value": "social"
                    },
                    {
                        "entity_locations": [
                            {
                                "element_path": "messenger.name",
                                "offsets": [
                                    0,
                                    8
                                ]
                            },
                            {
                                "element_path": "channel.messenger.name",
                                "offsets": [
                                    0,
                                    8
                                ]
                            }
                        ],
                        "extractor": "dtm-ma",
                        "extractor_version": "1.0.595",
                        "id": "dummay_topic_02",
                        "type": "service_name",
                        "value": "Googlechat"
                    }],
                "topics_url": "https://www.virustotal.com/v4/dtm/docs/message/dummy0001/topics",
                "updated_at": "2025-05-22T07:09:51.257Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### DTM Alerts
>
>|Alert ID|Title|Alert Summary|Alert Type|Severity|Status|Monitor ID|Monitor Name|Indicator Score|Created At|Updated At|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| dummy_0000 | Found topic "google" posted by actor "sevenbump" on channel "social" | This message advertises a service that provides fraudulent Google verification badges for any account. <br/> | Message | Low | Read | dummy_monitor_id | Initial Access Broker | 11 | 2025-05-21T11:28:02.646Z | 2025-05-22T07:09:51.257Z | attempt,<br/>Test |
>| dummy_0001 | Found topic "Google" posted by actor "sevenbump" on Google channel "social" | This message advertises a service that offers unauthorized google account.<br/> | Message | Low | Read | dummy_monitor_id | Initial Access Broker | 11 | 2025-05-21T10:19:04.241Z | 2025-05-22T07:09:51.257Z | attempt |

### gti-dtm-alert-get

***
Get a particular DTM Alert by ID.

#### Base Command

`gti-dtm-alert-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Specify ID of the alert.<br/><br/>Note: Use gti-dtm-alert-list to retrive the Alert ID. | Required |
| include_more_details | If yes, doc, labels, and topics are returned in the context data. Possible values are: Yes, No. Default is Yes. | Optional |
| sanitize | If yes, any HTML content in the alert is sanitized to ensure it does not contain malicious tags. Possible values are: Yes, No. | Optional |
| truncate | Specify whether to truncate document fields to the given length.<br/><br/>Note: A Unicode ellipsis (\x2026) is used to indicate truncation. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleThreatIntelligenceDTMAlerts.Alerts.id | String | Unique identifier for the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.monitor_id | String | Identifier of the monitoring source that generated the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.__id | String | Unique document ID associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.__type | String | Type of document associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.body | String | Full content or message body of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.channel_id | String | ID of the channel where the alert was observed. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.channel_info.description | String | Description of the channel where the alert was detected. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.channel_url | String | URL of the detected channel. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.invite_url | String | Invite link of the detected channel, if available. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.messenger.id | String | Identifier of the messenger platform linked to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.messenger.name | String | Name of the messenger platform. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.name | String | Name of the channel where the content was found. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.ingested | Date | Date and time when the document was ingested into the system. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.message_id | String | Identifier of the specific message triggering the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.messenger.id | String | Messenger platform ID associated with the message. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.messenger.name | String | Name of the messenger platform associated with the message. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.avatar_file.hashes.sha256 | String | SHA-256 hash of the sender's avatar file. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.avatar_file.mime_type | String | MIME type of the sender's avatar file. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.identity.first_name | String | First name of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.identity.last_name | String | Last name of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.identity.name | String | Full name of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.telegram.name | String | Telegram username of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.telegram.user_id | Number | Telegram user ID of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.source | String | Source of the document or content triggering the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.timestamp | Date | Timestamp when the message or document was created. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.id | String | Unique identifier of the label assigned to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.classifier | String | Classifier name used for label assignment. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.version | String | Version of the classifier or labeling process. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.label | String | Name of the label assigned to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.confidence | Number | Confidence score of the assigned label. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.element_path | String | Path of the element where the label was applied. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.id | String | Unique identifier of the extracted topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.type | String | Type of the extracted topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.value | String | Value of the extracted topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.extractor | String | Name of the topic extraction tool. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.extractor_version | String | Version of the topic extractor used. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.entity_locations.element_path | String | Path of the element where the entity was detected. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.entity_locations.offsets | Number | Character offsets of the detected entity in the document. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topic_matches.topic_id | String | Identifier of the matched topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topic_matches.value | String | Matched value for the topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.label_matches | List | List of labels matched for the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc_matches.match_path | String | Path within the document where a match occurred. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc_matches.locations.offsets | Number | Offset positions of the document match. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc_matches.locations.value | String | Value of the matched document content. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.tags | List | Tags associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.created_at | Date | Date and time when the alert was created. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.updated_at | Date | Date and time when the alert was last updated. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels_url | String | URL to fetch labels associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics_url | String | URL to fetch topics associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc_url | String | URL of the original document related to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.status | String | Current status of the alert \(e.g., open, closed, triaged\). |
| GoogleThreatIntelligenceDTMAlerts.Alerts.alert_type | String | Type or category of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.alert_summary | String | Summary of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.title | String | Title of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.email_sent_at | String | Timestamp when the alert email was sent. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.indicator_mscore | Number | Malicious score of the indicator related to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.severity | String | Severity level of the alert \(e.g., low, medium, high\). |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence | Number | Confidence score of the alert detection. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.aggregated_under_id | String | ID under which the alert has been aggregated. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.has_analysis | Boolean | Indicates whether the alert has an associated analysis. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.ai_doc_summary | String | AI-generated summary of the document related to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.similarity_score | Number | Similarity score between this alert and related alerts. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.severity_reasoning.rule | String | Rule used to determine the severity of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.version | String | Version of the confidence reasoning model. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.response_count | Number | Number of responses contributing to confidence reasoning. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.malicious_count | Number | Number of malicious detections contributing to confidence. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.benign_count | Number | Number of benign detections contributing to confidence. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.confidence_count | Number | Total number of samples considered for confidence calculation. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.explanation | String | Explanation behind the confidence score. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.ignore | Boolean | Indicates if the alert should be ignored. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.monitor_version | Number | Version of the monitoring source generating the alert. |

#### Command example

```!gti-dtm-alert-get alert_id=dummy_alert_001```

#### Context Example

```json
{
    "GoogleThreatIntelligenceDTMAlerts": {
        "Alerts": {
            "aggregated_under_id": "dummy_alert_001",
            "ai_doc_summary": "This advertisement details a sophisticated phishing-as-a-service platform verified email spoofing capabilities",
            "alert_summary": "Angel Mailer the best possible solution for all your mailing needs Our main features 1 1 Verified Mails with Checkmark on Google",
            "alert_type": "Message",
            "confidence": 0.5404703550433493,
            "confidence_reasoning": {
                "benign_count": 0,
                "malicious_count": 0,
                "response_count": 0,
                "version": ""
            },
            "created_at": "2025-08-19T09:29:31.827Z",
            "doc": {
                "__id": "dummy",
                "__type": "message",
                "body": "Welcome to Angel Mailer, the best possible solution for all your mailing needs. \n\nOur main features:\n\n💎 1:1 Verified Mails with Checkmark on googl/AOL\n\n A lot of templates with a choice of spoof.",
                "channel": {
                    "channel_id": "dummy",
                    "channel_info": {
                        "description": "chasingchicken"
                    },
                    "channel_url": "DUMMY",
                    "invite_url": "DUMMY",
                    "messenger": {
                        "id": "google",
                        "name": "Google"
                    },
                    "name": "dummy"
                },
                "ingested": "2025-08-19T08:43:20Z",
                "message_id": "dummy",
                "messenger": {
                    "id": "google",
                    "name": "Google"
                },
                "parts": [
                    {
                        "content_type": "video/mp4",
                        "filename": "angelmailerready.mp4"
                    }
                ],
                "sender": {
                    "identity": {
                        "first_name": "dummy_xyz",
                        "name": "dummy_xyz"
                    },
                    "google": {
                        "user_id": 157338048
                    }
                },
                "source": "Google",
                "timestamp": "2025-08-19T08:43:16Z"
            },
            "doc_matches": [
                {
                    "locations": [
                        {
                            "offsets": [
                                395,
                                399
                            ],
                            "value": "full"
                        }
                    ],
                    "match_path": "body"
                }
            ],
            "doc_url": "https://www.virustotal.com/v4/dtm/docs/message/dummy",
            "email_sent_at": "",
            "has_analysis": false,
            "id": "dummy_alert_001",
            "ignore": false,
            "indicator_mscore": 92,
            "labels": [
                {
                    "classifier": "classifier-content",
                    "confidence": 100,
                    "element_path": "body",
                    "id": "dummy",
                    "label": "prose",
                    "version": "2-0-0"
                },
                {
                    "classifier": "classifier-language",
                    "confidence": 76,
                    "element_path": "body",
                    "id": "dummy",
                    "label": "en",
                    "version": "1-0-0"
                },
                {
                    "classifier": "classifier-threat",
                    "confidence": 100,
                    "id": "dummy",
                    "label": "information-security/anonymization",
                    "version": "3-0-0"
                }
            ],
            "labels_url": "https://www.virustotal.com/v4/dtm/docs/message/dummy/labels",
            "monitor_id": "dummy_monitor_id_000",
            "monitor_version": 1,
            "severity": "medium",
            "severity_reasoning": {
                "rule": ""
            },
            "similarity_score": 0.9554455,
            "status": "new",
            "tags": [
                "attempt"
            ],
            "title": "Found topic \"google\" posted by actor \"test \" on channel \"chasinchicken1\"",
            "topic_matches": [
                {
                    "offsets": [
                        0,
                        6
                    ],
                    "term": "google",
                    "topic_id": "dummy",
                    "value": "Google"
                },
                {
                    "topic_id": "doc_type:message",
                    "value": "message"
                }
            ],
            "topics": [
                {
                    "confidence": 81,
                    "entity_locations": [
                        {
                            "element_path": "body",
                            "offsets": [
                                666,
                                674
                            ]
                        }
                    ],
                    "extractor": "analysis-pipeline.nerprocessor-nerenglish-gpu",
                    "extractor_version": "4-0-2",
                    "id": "dummy",
                    "type": "product",
                    "value": "Google"
                },
                {
                    "confidence": 100,
                    "entity_locations": [
                        {
                            "element_path": "body",
                            "offsets": [
                                262,
                                267,
                                1183,
                                1188
                            ]
                        }
                    ],
                    "extractor": "dummy_extractor",
                    "extractor_version": "4-0-2",
                    "id": "dummy",
                    "type": "organization",
                    "value": "Google"
                }
            ],
            "topics_url": "https://www.virustotal.com/v4/dtm/docs/message/dummy/topics",
            "updated_at": "2025-08-19T10:13:25.352Z"
        }
    }
}
```

#### Human Readable Output

>### DTM Alert
>
>|Alert ID|Title|Alert Summary|Alert Type|Severity|Status|Monitor ID|Indicator Score|Created At|Updated At|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|
>| dummy_alert_001 | Found topic "google" posted by actor "test" on channel "chasinchicken1" | This advertisement details a sophisticated phishing-as-a-service platform verified email spoofing capabilities.| Message | Medium | New | dummy_monitor_id_000 | 92 | 2025-08-19T09:29:31.827Z | 2025-08-19T10:13:25.352Z | attempt |

### gti-dtm-alert-status-update

***
Update the status of DTM alert.

#### Base Command

`gti-dtm-alert-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Specify ID of the alert.<br/><br/>Note: Use gti-dtm-alert-list to retrive the Alert ID. | Required |
| status | Specify status of the alert. Possible values are: new, read, in_progress, escalated, closed, no_action_required, duplicate, not_relevant, tracked_external. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleThreatIntelligenceDTMAlerts.Alerts.id | String | Unique identifier for the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.monitor_id | String | Identifier of the monitoring source that generated the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.__id | String | Unique document ID associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.__type | String | Type of document associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.body | String | Full content or message body of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.channel_id | String | ID of the channel where the alert was observed. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.channel_info.description | String | Description of the channel where the alert was detected. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.channel_url | String | URL of the detected channel. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.invite_url | String | Invite link of the detected channel, if available. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.messenger.id | String | Identifier of the messenger platform linked to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.messenger.name | String | Name of the messenger platform. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.channel.name | String | Name of the channel where the content was found. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.ingested | Date | Date and time when the document was ingested into the system. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.message_id | String | Identifier of the specific message triggering the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.messenger.id | String | Messenger platform ID associated with the message. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.messenger.name | String | Name of the messenger platform associated with the message. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.avatar_file.hashes.sha256 | String | SHA-256 hash of the sender's avatar file. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.avatar_file.mime_type | String | MIME type of the sender's avatar file. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.identity.first_name | String | First name of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.identity.last_name | String | Last name of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.identity.name | String | Full name of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.telegram.name | String | Telegram username of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.sender.telegram.user_id | Number | Telegram user ID of the sender. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.source | String | Source of the document or content triggering the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc.timestamp | Date | Timestamp when the message or document was created. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.id | String | Unique identifier of the label assigned to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.classifier | String | Classifier name used for label assignment. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.version | String | Version of the classifier or labeling process. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.label | String | Name of the label assigned to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.confidence | Number | Confidence score of the assigned label. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels.element_path | String | Path of the element where the label was applied. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.id | String | Unique identifier of the extracted topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.type | String | Type of the extracted topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.value | String | Value of the extracted topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.extractor | String | Name of the topic extraction tool. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.extractor_version | String | Version of the topic extractor used. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.entity_locations.element_path | String | Path of the element where the entity was detected. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics.entity_locations.offsets | Number | Character offsets of the detected entity in the document. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topic_matches.topic_id | String | Identifier of the matched topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topic_matches.value | String | Matched value for the topic. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.label_matches | List | List of labels matched for the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc_matches.match_path | String | Path within the document where a match occurred. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc_matches.locations.offsets | Number | Offset positions of the document match. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc_matches.locations.value | String | Value of the matched document content. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.tags | List | Tags associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.created_at | Date | Date and time when the alert was created. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.updated_at | Date | Date and time when the alert was last updated. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.labels_url | String | URL to fetch labels associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.topics_url | String | URL to fetch topics associated with the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.doc_url | String | URL of the original document related to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.status | String | Current status of the alert \(e.g., open, closed, triaged\). |
| GoogleThreatIntelligenceDTMAlerts.Alerts.alert_type | String | Type or category of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.alert_summary | String | Summary of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.title | String | Title of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.email_sent_at | String | Timestamp when the alert email was sent. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.indicator_mscore | Number | Malicious score of the indicator related to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.severity | String | Severity level of the alert \(e.g., low, medium, high\). |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence | Number | Confidence score of the alert detection. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.aggregated_under_id | String | ID under which the alert has been aggregated. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.has_analysis | Boolean | Indicates whether the alert has an associated analysis. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.ai_doc_summary | String | AI-generated summary of the document related to the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.similarity_score | Number | Similarity score between this alert and related alerts. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.severity_reasoning.rule | String | Rule used to determine the severity of the alert. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.version | String | Version of the confidence reasoning model. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.response_count | Number | Number of responses contributing to confidence reasoning. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.malicious_count | Number | Number of malicious detections contributing to confidence. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.benign_count | Number | Number of benign detections contributing to confidence. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.confidence_count | Number | Total number of samples considered for confidence calculation. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.confidence_reasoning.explanation | String | Explanation behind the confidence score. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.ignore | Boolean | Indicates if the alert should be ignored. |
| GoogleThreatIntelligenceDTMAlerts.Alerts.monitor_version | Number | Version of the monitoring source generating the alert. |

#### Command example

```!gti-dtm-alert-status-update alert_id=dummyalertid_001 status=duplicate```

#### Context Example

```json
{
    "GoogleThreatIntelligenceDTMAlerts": {
        "Alerts": {
            "aggregated_under_id": "dummy_monitor_id_001",
            "ai_doc_summary": "This advertisement for \"Angel Mailer\" highlights its capabilities for sending spoofed emails.",
            "alert_summary": "Angel Mailer the best possible solution for all your mailing needs Our main features…",
            "alert_type": "Message",
            "confidence": 0.5404703550433493,
            "confidence_reasoning": {
                "benign_count": 0,
                "malicious_count": 0,
                "response_count": 0,
                "version": ""
            },
            "created_at": "2025-08-27T19:05:38.521Z",
            "doc_matches": [
                {
                    "locations": [
                        {
                            "value": "full"
                        }
                    ],
                    "match_path": "body"
                }
            ],
            "doc_url": "https://www.virustotal.com/v4/dtm/docs/message/dummyid",
            "email_sent_at": "",
            "has_analysis": false,
            "id": "dummy_alert_id_001",
            "ignore": false,
            "indicator_mscore": 92,
            "labels_url": "https:///www.virustotal.com/v4/dtm/docs/message/dummyid/labels",
            "monitor_id": "dummy_monitor_id",
            "monitor_version": 1,
            "severity": "medium",
            "severity_reasoning": {
                "rule": ""
            },
            "similarity_score": 0.9554455,
            "status": "duplicate",
            "title": "Found topic \"google\" posted by actor \"test\" on Telegram channel \"chasinchicken1\"",
            "topic_matches": [
                {
                    "offsets": [
                        0,
                        6
                    ],
                    "term": "google",
                    "topic_id": "000101000010",
                    "value": "Google"
                },
                {
                    "topic_id": "doc_type:message",
                    "value": "message"
                }
            ],
            "topics_url": "https:///www.virustotal.com/topics",
            "updated_at": "2025-08-28T06:25:10.535Z"
        }
    }
}
```

#### Human Readable Output

>### Alert Status Updated Successfully
>
>|Alert ID|Status|
>|---|---|
>| dummy_alert_id_001 | Duplicate |
