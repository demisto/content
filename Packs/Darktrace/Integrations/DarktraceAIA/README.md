Darktrace is a Cyber AI platform for threat detection and response across cloud, email, industrial, and the network.
This integration was integrated and tested with version 6.0.0 of Darktrace

## Configure Darktrace in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| isFetch | Fetch incidents | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| public_api_token | Public API Token | True |
| private_api_token | Private API Token | True |
| min_score | Minimum Score | True |
| max_alerts | Maximum Model Breaches per Fetch | False |
| first_fetch | First fetch time | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### darktrace-get-ai-analyst-incident-event

***
Returns all AI Analyst incident events

#### Base Command

`darktrace-get-ai-analyst-incident-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventId |Unique identified of an AI Analyst incident event | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.AIAnalyst.eventId | Unknown | AIAnalyst unique identifier |
| Darktrace.AIAnalyst.title | String | AIAnalyst event title |
| Darktrace.AIAnalyst.mitreTactics | Unknown | AIAnalyst mitre tactics seen on event |
| Darktrace.AIAnalyst.score | Unknown | group score for ai analyst incident |
| Darktrace.AIAnalyst.category | String | group category for ai analyst incident |
| Darktrace.AIAnalyst.summary | String | AIAnalyst event summary |
| Darktrace.AIAnalyst.groupId | Unknown | unique identifier for event Id |
| Darktrace.AIAnalyst.devices | Unknown | Associated devices with incident event |
| Darktrace.AIAnalyst.modelBreaches | Unknown | Associated model breaches with event Id |

### darktrace-get-comments-for-ai-analyst-incident-event

***
Returns all Darktrace Comments for a given Incident Event

#### Base Command

`darktrace-get-comments-for-ai-analyst-incident-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventId |Unique identified of an AI Analyst incident event | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.AIAnalyst.incidet_id | Number | Incident event unique identifier |
| Darktrace.AIAnalyst.message | String | Posted message |
| Darktrace.AIAnalyst.eventId | String | Unique event identifier |
| Darktrace.AIAnalyst.time | String | Message post timestamp |
| Darktrace.AIAnalyst.username | String | Darktrace username of posting user |

### darktrace-post-comment-to-ai-analyst-incident-event

***
Post comment to an AI Analyst Incident Event.

#### Base Command

`darktrace-post-comment-to-ai-analyst-incident-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventId | Unique identified of an AI Analyst incident event | Required |
| comment | Enter a message to comment | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.AIAnalyst.commented | String | Whether the incident is commented in Darktrace |
| Darktrace.AIAnalyst.response | String | Post command response |
| Darktrace.AIAnalyst.eventId | String | Unique event identifier |
| Darktrace.AIAnalyst.message | String | Message to be commented |

### darktrace-acknowledge-ai-analyst-incident-event

***
Acknowledges an AI Analyst Incident Event

#### Base Command

`darktrace-acknowledge-ai-analyst-incident-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventId | Unique identified of an AI Analyst incident event | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.AIAnalyst.acknowledged | String | Whether the incident is acknowledge in Darktrace |
| Darktrace.AIAnalyst.response | String | Post response comment |
| Darktrace.AIAnalyst.eventId | String | incident event unique identifier |

### darktrace-unacknowledge-ai-analyst-incident-event

***
Unacknowledges an AI Analyst Incident Event

#### Base Command

`darktrace-unacknowledge-ai-analyst-incident-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventId | Unique identified of an AI Analyst incident event | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.AIAnalyst.unacknowledged | String | Whether the incident is acknowledge in Darktrace |
| Darktrace.AIAnalyst.response | String | Post response comment |
| Darktrace.AIAnalyst.eventId | String | incident event unique identifier |

### darktrace-get-ai-analyst-incident-group-from-eventId

***
Pulls all linked events for a given event. Over time, events can become merged with one another. This happens when two sets of disparate activity are suddenly linked by shared factors.

#### Base Command

`darktrace-get-ai-analyst-incident-group-from-eventId`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventId | Unique identified of an AI Analyst incident event | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.AIAnalyst.groupId | String | Investigation Group Unique Identifier |
| Darktrace.AIAnalyst.incidentEvents | Unknown | Associated events |
| Darktrace.AIAnalyst.mitreTactics | Unknown | Associated Mitre Tactics seen on incident |
| Darktrace.AIAnalyst.groupScore | Number | Group score |
| Darktrace.AIAnalyst.groupCategory | String | Group category |