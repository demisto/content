The Trustwave Fusion platform connects your organization’s digital footprint
to a robust security cloud comprised of the Trustwave data lake, advanced
analytics, actionable threat intelligence and a wide range of Trustwave
services including Trustwave SpiderLabs , elite team of security
specialists. Your team will benefit from deep visibility and the advanced
security expertise necessary for protecting assets and eradicating threats as
they arise.

This integration was integrated and tested with version 1.0.68 of TrustwaveFusion

## Configure TrustwaveFusion in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fusion API URL |  | True |
| API Key | The API Key to use for connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Maximum number of incidents per fetch |  | False |
| First fetch time | Format: \[number\] \[time unit\]. e.g., 12 hours, 7 days, 2 seconds etc. | False |
| Ticket Types | Types of tickets to fetch | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### trustwave-get-ticket
***
Get a single ticket


#### Base Command

`trustwave-get-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trustwave.Ticket.number | String | The Ticket ID | 
| Trustwave.Ticket.subject | String | The ticket title. | 
| Trustwave.Ticket.status | String | The status of the ticket | 
| Trustwave.Ticket.description | String | The detailed ticket description. | 
| Trustwave.Ticket.category | String | Ticket category | 
| Trustwave.Ticket.createdBy | String | User that created the ticket. | 
| Trustwave.Ticket.createdOn | Date | The ticket creation time. | 
| Trustwave.Ticket.customerName | String | The name of the customer. | 
| Trustwave.Ticket.findings.classification | String | Category for finding related to the ticket. | 
| Trustwave.Ticket.findings.classificationCode | String | Category code for finding related to the ticket. | 
| Trustwave.Ticket.findings.findingId | String | Id finding related to the ticket. | 
| Trustwave.Ticket.formatted_notes | String | Human readable Notes for the ticket. | 
| Trustwave.Ticket.impact | String | Ticket impact \(HIGH, MEDIUM, LOW\) | 
| Trustwave.Ticket.notes.actor | String | User that added the note \(comment\) | 
| Trustwave.Ticket.notes.text | String | The note \(comment\) text. | 
| Trustwave.Ticket.notes.timestamp | Date | Time when the note \(comment\) was created. | 
| Trustwave.Ticket.priority | String | Ticket priority \(CRITICAL, HIGH, MEDIUM, LOW\) | 
| Trustwave.Ticket.subCategory | String | Ticket sub-category. | 
| Trustwave.Ticket.type | String | The ticket type \(CASE, INCIDENT, CHANGE\) | 
| Trustwave.Ticket.updatedOn | Date | When the ticket was last updated. | 
| Trustwave.Ticket.urgency | String | The ticket urgency \(HIGH, MEDIUM, LOW\) | 

#### Command example
```!trustwave-get-ticket id="INA1976568"```
#### Context Example
```json
{
    "Trustwave": {
        "Ticket": {
            "assetIds": [],
            "category": "Threat Detection & Response",
            "createdBy": "dummyuser",
            "createdOn": "2021-12-08T17:16:27.000+00:00",
            "customerName": "Sample Customer",
            "description": "Ticket description.",
            "findings": [
                {
                    "classification": null,
                    "classificationCode": "UnauthorizedAccessOrIntrusionAttempt.",
                    "findingId": "765432:THREAT:@AXv0k6GhG2zTcaogE1vG"
                }
            ],
            "formatted_notes": "2021-12-08T17:16:27.000+00:00 Created by: dummyuser\nNOTE:\nNote A\n----------------\n2021-12-08T17:17:57.000+00:00 Created by: dummyuser\nNOTE:\nNote B\n----------------\n2021-12-09T16:43:31.000+00:00 Created by: dummy_user\nNOTE:\nNote C",
            "impact": "HIGH",
            "notes": [
                {
                    "actor": "dummyuser",
                    "text": "Note A",
                    "timestamp": "2021-12-08T17:16:27.000+00:00"
                },
                {
                    "actor": "dummyuser",
                    "text": "Note B",
                    "timestamp": "2021-12-08T17:17:57.000+00:00"
                },
                {
                    "actor": "dummy_user",
                    "text": "Note C",
                    "timestamp": "2021-12-09T16:43:31.000+00:00"
                }
            ],
            "number": "INA1976568",
            "priority": "HIGH",
            "status": "ON_HOLD",
            "subCategory": "Threat Operations",
            "subject": "Test incident #354",
            "type": "INCIDENT",
            "updatedOn": "2021-12-09T16:43:48.000+00:00",
            "urgency": "MEDIUM"
        }
    }
}
```

#### Human Readable Output

>| field | value |
>|-|-|
>| assetIds |  |
>| category | Threat Detection & Response |
>| createdBy | dummyuser |
>| createdOn | 2021-12-08T17:16:27.000+00:00 |
>| customerName | Sample Customer |
>| description | Ticket description. |
>| findings | {'classification': None, 'classificationCode': 'UnauthorizedAccessOrIntrusionAttempt.', 'findingId': '765432:THREAT:@AXv0k6GhG2zTcaogE1vG'} |
>| impact | HIGH |
>| notes | {'actor': 'dummyuser', 'text': 'Note A', 'timestamp': '2021-12-08T17:16:27.000+00:00'},<br/>{'actor': 'dummyuser', 'text': 'Note B', 'timestamp': '2021-12-08T17:17:57.000+00:00'},<br/>{'actor': 'dummy_u....[Truncated] |
>| number | INA1976568 |
>| priority | HIGH |
>| status | ON_HOLD |
>| subCategory | Threat Operations |
>| subject | Test incident #354 |
>| type | INCIDENT |
>| updatedOn | 2021-12-09T16:43:48.000+00:00 |
>| urgency | MEDIUM |
>| formatted_notes | 2021-12-08T17:16:27.000+00:00 Created by: dummyuser<br/>NOTE:<br/>Note A<br/>----------------<br/>2021-12-08T17:17:57.000+00:00 Created by: dummyuser<br/>NOTE:<br/>Note B<br/>----------------<br/>2021-12-09T1....[Truncated] |

### trustwave-search-tickets
***
Search tickets


#### Base Command

`trustwave-search-tickets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket ID. | Optional | 
| subject | Ticket Subject. | Optional | 
| type | Ticket type to query. Possible values are: INCIDENT, CASE, CHANGE. | Optional | 
| status | Ticket status. Possible values are: NEW, OPEN, IN_PROGRESS, AWAITING_INFO, ON_HOLD, RESOLVED, CLOSED, CANCELED, SCHEDULED. | Optional | 
| priority | Ticket priority. Possible values are: CRITICAL, HIGH, MEDIUM, LOW. | Optional | 
| impact | Ticket impact. Possible values are: HIGH, MEDIUM, LOW. | Optional | 
| urgency | Ticket urgency. Possible values are: HIGH, MEDIUM, LOW. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trustwave.Ticket.number | String | The Ticket ID | 
| Trustwave.Ticket.subject | String | The ticket title. | 
| Trustwave.Ticket.status | String | The status of the ticket | 
| Trustwave.Ticket.description | String | The detailed ticket description. | 
| Trustwave.Ticket.category | String | Ticket category. | 
| Trustwave.Ticket.createdBy | String | User that created the ticket. | 
| Trustwave.Ticket.createdOn | Date | The time when the ticket was created. | 
| Trustwave.Ticket.customerName | String | The name of the customer. | 
| Trustwave.Ticket.formatted_notes | String | Human readable notes. | 
| Trustwave.Ticket.impact | String | Ticket impact \(HIGH, MEDIUM, LOW\) | 
| Trustwave.Ticket.notes.actor | String | User that added the note \(comment\) | 
| Trustwave.Ticket.notes.text | String | The note \(comment\) text. | 
| Trustwave.Ticket.notes.timestamp | Date | Time when the note \(comment\) was created. | 
| Trustwave.Ticket.priority | String | Ticket priority \(CRITICAL, HIGH, MEDIUM, LOW\) | 
| Trustwave.Ticket.subCategory | String | Ticket sub-category. | 
| Trustwave.Ticket.type | String | The ticket type \(CASE, INCIDENT, CHANGE\) | 
| Trustwave.Ticket.updatedOn | Date | When the ticket was last updated. | 
| Trustwave.Ticket.urgency | String | The ticket urgency \(HIGH, MEDIUM, LOW\) | 

#### Command example
```!trustwave-search-tickets limit=2 type=INCIDENT ```
#### Context Example
```json
{
    "Trustwave": {
        "Ticket": [
            {
                "assetIds": [
                    "765432:managed-device#DEVICE:AW8Qp1Bextjwd2cF57Mk"
                ],
                "category": "Technology Management",
                "createdBy": "cpe_outage_service",
                "createdOn": "2021-11-29T10:56:45.000+00:00",
                "customerName": "Sample Customer",
                "description": "",
                "findings": [],
                "formatted_notes": "2021-11-29T10:56:44.000+00:00 Created by: cpe_outage_service\nNOTE:\nNOTE A",
                "impact": "HIGH",
                "notes": [
                    {
                        "actor": "cpe_outage_service",
                        "text": "NOTE A",
                        "timestamp": "2021-11-29T10:56:44.000+00:00"
                    }
                ],
                "number": "INA1077007",
                "priority": "HIGH",
                "status": "CLOSED",
                "subCategory": "Cellular Backup",
                "subject": "Alert: device is using cellular",
                "type": "INCIDENT",
                "updatedOn": "2021-12-29T00:00:08.000+00:00",
                "urgency": "MEDIUM"
            },
            {
                "assetIds": [],
                "category": "Threat Detection & Response",
                "createdBy": "dummyuser",
                "createdOn": "2021-12-08T17:16:27.000+00:00",
                "customerName": "Sample Customer",
                "description": "Ticket description",
                "findings": [
                    {
                        "classification": null,
                        "classificationCode": "UnauthorizedAccessOrIntrusionAttempt.",
                        "findingId": "765432:THREAT:@AXv0k6GhG2zTcaogE1vG"
                    }
                ],
                "formatted_notes": "2021-12-08T17:16:27.000+00:00 Created by: dummyuser\nNOTE:\nSample Note.\n----------------\n2021-12-08T17:17:57.000+00:00 Created by: dummyuser\nNOTE:\nSample note #2.\n----------------\n2021-12-09T16:43:31.000+00:00 Created by: dummy_user\nNOTE:\nSample note #3",
                "impact": "HIGH",
                "notes": [
                    {
                        "actor": "dummyuser",
                        "text": "Sample Note.",
                        "timestamp": "2021-12-08T17:16:27.000+00:00"
                    },
                    {
                        "actor": "dummyuser",
                        "text": "Sample note #2.",
                        "timestamp": "2021-12-08T17:17:57.000+00:00"
                    },
                    {
                        "actor": "dummy_user",
                        "text": "Sample note #3",
                        "timestamp": "2021-12-09T16:43:31.000+00:00"
                    }
                ],
                "number": "INA1077535",
                "priority": "HIGH",
                "status": "ON_HOLD",
                "subCategory": "Threat Operations",
                "subject": "MCAS - Impossible travel activity",
                "type": "INCIDENT",
                "updatedOn": "2021-12-09T16:43:48.000+00:00",
                "urgency": "MEDIUM"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|assetIds|category|createdBy|createdOn|customerName|description|findings|formatted_notes|impact|notes|number|priority|status|subCategory|subject|type|updatedOn|urgency|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 765432:managed-device#DEVICE:AW8Qp1Bextjwd2cF57Mk | Technology Management | cpe_outage_service | 2021-11-29T10:56:45.000+00:00 | Sample Customer |  |  | 2021-11-29T10:56:44.000+00:00 Created by: cpe_outage_service<br/>NOTE:<br/>NOTE A | HIGH | {'actor': 'cpe_outage_service', 'text': 'NOTE A', 'timestamp': '2021-11-29T10:56:44.000+00:00'} | INA1077007 | HIGH | CLOSED | Cellular Backup | Alert: device is using cellular | INCIDENT | 2021-12-29T00:00:08.000+00:00 | MEDIUM |
>|  | Threat Detection & Response | dummyuser | 2021-12-08T17:16:27.000+00:00 | Sample Customer | Ticket description | {'classification': None, 'classificationCode': 'UnauthorizedAccessOrIntrusionAttempt.', 'findingId': '765432:THREAT:@AXv0k6GhG2zTcaogE1vG'} | 2021-12-08T17:16:27.000+00:00 Created by: dummyuser<br/>NOTE:<br/>Sample Note.<br/>----------------<br/>2021-12-08T17:17:57.000+00:00 Created by: dummyuser<br/>NOTE:<br/>Sample note #2.<br/>----------------<br/>2021-12-09T16:43:31.000+00:00 Created by: dummy_user<br/>NOTE:<br/>Sample note #3 | HIGH | {'actor': 'dummyuser', 'text': 'Sample Note.', 'timestamp': '2021-12-08T17:16:27.000+00:00'},<br/>{'actor': 'dummyuser', 'text': 'Sample note #2.', 'timestamp': '2021-12-08T17:17:57.000+00:00'},<br/>{'actor': 'dummy_user', 'text': 'Sample note #3', 'timestamp': '2021-12-09T16:43:31.000+00:00'} | INA1077535 | HIGH | ON_HOLD | Threat Operations | MCAS - Impossible travel activity | INCIDENT | 2021-12-09T16:43:48.000+00:00 | MEDIUM |


### trustwave-add-ticket-comment
***
Add a comment to a ticket


#### Base Command

`trustwave-add-ticket-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Incident ID. | Required | 
| comment | Comment text. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!trustwave-add-ticket-comment id=INA1051028 comment="test from xsoar"```
#### Human Readable Output

>Success

### trustwave-close-ticket
***
Close a ticket


#### Base Command

`trustwave-close-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Incident ID. | Required | 
| comment | Comment text. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!trustwave-close-ticket id="INA1051028" comment="Comment"```
#### Human Readable Output

>Success

### trustwave-get-updated-tickets
***
Get updated tickets.


#### Base Command

`trustwave-get-updated-tickets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | Absolute or relative date to check for updates. | Required | 
| fetch_limit | Maximum number of tickets to fetch. Default is 100. | Optional | 
| ticket_types | Ticket type to query. Possible values are: INCIDENT, CASE, CHANGE. Default is INCIDENT. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trustwave.Ticket.number | String | The Ticket ID | 
| Trustwave.Ticket.subject | String | The ticket title. | 
| Trustwave.Ticket.status | String | The status of the ticket | 
| Trustwave.Ticket.description | String | The detailed ticket description. | 
| Trustwave.Ticket.category | String | Ticket category. | 
| Trustwave.Ticket.createdBy | String | User that created the ticket. | 
| Trustwave.Ticket.createdOn | Date | The time when the ticket was created. | 
| Trustwave.Ticket.customerName | String | The name of the customer. | 
| Trustwave.Ticket.formatted_notes | String | Human readable notes. | 
| Trustwave.Ticket.impact | String | Ticket impact \(HIGH, MEDIUM, LOW\) | 
| Trustwave.Ticket.notes.actor | String | User that added the note \(comment\) | 
| Trustwave.Ticket.notes.text | String | The note \(comment\) text. | 
| Trustwave.Ticket.notes.timestamp | Date | Time when the note \(comment\) was created. | 
| Trustwave.Ticket.priority | String | Ticket priority \(CRITICAL, HIGH, MEDIUM, LOW\) | 
| Trustwave.Ticket.subCategory | String | Ticket sub-category. | 
| Trustwave.Ticket.type | String | The ticket type \(CASE, INCIDENT, CHANGE\) | 
| Trustwave.Ticket.updatedOn | Date | When the ticket was last updated. | 
| Trustwave.Ticket.urgency | String | The ticket urgency \(HIGH, MEDIUM, LOW\) | 

#### Command example
```!trustwave-get-updated-tickets fetch_limit=2 since=2021-12-09T16:43:48.000+00:00```
#### Context Example
```json
{
    "Trustwave": {
        "Ticket": [
            {
                "assetIds": [
                    "765432:managed-device#DEVICE:AW8Qp1Bextjwd2cF57Mk"
                ],
                "category": "Technology Management",
                "createdBy": "cpe_outage_service",
                "createdOn": "2021-11-29T10:56:45.000+00:00",
                "customerName": "Sample Customer",
                "description": "",
                "findings": [],
                "formatted_notes": "2021-11-29T10:56:44.000+00:00 Created by: cpe_outage_service\nNOTE:\nNOTE A",
                "impact": "HIGH",
                "notes": [
                    {
                        "actor": "cpe_outage_service",
                        "text": "NOTE A",
                        "timestamp": "2021-11-29T10:56:44.000+00:00"
                    }
                ],
                "number": "INA1077007",
                "priority": "HIGH",
                "status": "CLOSED",
                "subCategory": "Cellular Backup",
                "subject": "Alert: device is using cellular",
                "type": "INCIDENT",
                "updatedOn": "2021-12-29T00:00:08.000+00:00",
                "urgency": "MEDIUM"
            },
            {
                "assetIds": [],
                "category": "Threat Detection & Response",
                "createdBy": "dummyuser",
                "createdOn": "2021-12-08T17:16:27.000+00:00",
                "customerName": "Sample Customer",
                "description": "Ticket description",
                "findings": [
                    {
                        "classification": null,
                        "classificationCode": "UnauthorizedAccessOrIntrusionAttempt.",
                        "findingId": "765432:THREAT:@AXv0k6GhG2zTcaogE1vG"
                    }
                ],
                "formatted_notes": "2021-12-08T17:16:27.000+00:00 Created by: dummyuser\nNOTE:\nSample Note.\n----------------\n2021-12-08T17:17:57.000+00:00 Created by: dummyuser\nNOTE:\nSample note #2.\n----------------\n2021-12-09T16:43:31.000+00:00 Created by: dummy_user\nNOTE:\nSample note #3",
                "impact": "HIGH",
                "notes": [
                    {
                        "actor": "dummyuser",
                        "text": "Sample Note.",
                        "timestamp": "2021-12-08T17:16:27.000+00:00"
                    },
                    {
                        "actor": "dummyuser",
                        "text": "Sample note #2.",
                        "timestamp": "2021-12-08T17:17:57.000+00:00"
                    },
                    {
                        "actor": "dummy_user",
                        "text": "Sample note #3",
                        "timestamp": "2021-12-09T16:43:31.000+00:00"
                    }
                ],
                "number": "INA1077535",
                "priority": "HIGH",
                "status": "ON_HOLD",
                "subCategory": "Threat Operations",
                "subject": "MCAS - Impossible travel activity",
                "type": "INCIDENT",
                "updatedOn": "2021-12-09T16:43:48.000+00:00",
                "urgency": "MEDIUM"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|assetIds|category|createdBy|createdOn|customerName|description|findings|formatted_notes|impact|notes|number|priority|status|subCategory|subject|type|updatedOn|urgency|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 765432:managed-device#DEVICE:AW8Qp1Bextjwd2cF57Mk | Technology Management | cpe_outage_service | 2021-11-29T10:56:45.000+00:00 | Sample Customer |  |  | 2021-11-29T10:56:44.000+00:00 Created by: cpe_outage_service<br/>NOTE:<br/>NOTE A | HIGH | {'actor': 'cpe_outage_service', 'text': 'NOTE A', 'timestamp': '2021-11-29T10:56:44.000+00:00'} | INA1077007 | HIGH | CLOSED | Cellular Backup | Alert: device is using cellular | INCIDENT | 2021-12-29T00:00:08.000+00:00 | MEDIUM |
>|  | Threat Detection & Response | dummyuser | 2021-12-08T17:16:27.000+00:00 | Sample Customer | Ticket description | {'classification': None, 'classificationCode': 'UnauthorizedAccessOrIntrusionAttempt.', 'findingId': '765432:THREAT:@AXv0k6GhG2zTcaogE1vG'} | 2021-12-08T17:16:27.000+00:00 Created by: dummyuser<br/>NOTE:<br/>Sample Note.<br/>----------------<br/>2021-12-08T17:17:57.000+00:00 Created by: dummyuser<br/>NOTE:<br/>Sample note #2.<br/>----------------<br/>2021-12-09T16:43:31.000+00:00 Created by: dummy_user<br/>NOTE:<br/>Sample note #3 | HIGH | {'actor': 'dummyuser', 'text': 'Sample Note.', 'timestamp': '2021-12-08T17:16:27.000+00:00'},<br/>{'actor': 'dummyuser', 'text': 'Sample note #2.', 'timestamp': '2021-12-08T17:17:57.000+00:00'},<br/>{'actor': 'dummy_user', 'text': 'Sample note #3', 'timestamp': '2021-12-09T16:43:31.000+00:00'} | INA1077535 | HIGH | ON_HOLD | Threat Operations | MCAS - Impossible travel activity | INCIDENT | 2021-12-09T16:43:48.000+00:00 | MEDIUM |


### trustwave-search-findings
***
Search for Findings


#### Base Command

`trustwave-search-findings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Finding ID. | Optional | 
| limit | Maximum number of Findings to return. Default is 100. | Optional | 
| name | Name of the Finding. | Optional | 
| classification | Finding Classification. | Optional | 
| summary | Finding summary. | Optional | 
| detail | Finding detail. | Optional | 
| priority | Finding priority. Possible values are: CRITICAL, HIGH, MEDIUM, LOW. | Optional | 
| severity | Finding severity. | Optional | 
| created_since | created_since. | Optional | 
| updated_since | Updated since. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trustwave.Finding.classification | String | Category for the finding | 
| Trustwave.Finding.createdOn | Date | Time when the finding was created. | 
| Trustwave.Finding.customerName | String | Customer name for the finding. | 
| Trustwave.Finding.destination | String | Destination for finding. | 
| Trustwave.Finding.detail | String | Detailed description of the finding. | 
| Trustwave.Finding.id | String | The finding ID | 
| Trustwave.Finding.priority | Number | The priority of the finding. | 
| Trustwave.Finding.severity | Number | The severity of the finding. | 
| Trustwave.Finding.source | String | SOAR actions taken for finding. | 
| Trustwave.Finding.status.description | String | Current status of the Finding. | 
| Trustwave.Finding.summary | String | The name of the finding. | 
| Trustwave.Finding.type | String | The type of finding \(e.g. THREAT, VULNERABILITY\) | 
| Trustwave.Finding.updatedOn | Date | Time when the finding was last updated. | 

#### Command example
```!trustwave-search-findings limit="2" summary="MS Graph Alert Detection Rule" type=threat updatedSince=2021-12-08T17:17:56.000+00:00```
#### Context Example
```json
{
    "Trustwave": {
        "Finding": [
            {
                "classification": null,
                "createdOn": "2021-09-17T16:26:11.731+00:00",
                "customerName": "Sample Customer",
                "destination": null,
                "detail": "MCAS - Impossible travel activity",
                "id": "765432:THREAT:@AXv0k6GhG2zTcaogE1vG",
                "priority": 4,
                "severity": 4,
                "source": null,
                "status": {
                    "description": "Security Incident"
                },
                "summary": "MS Graph Alert Detection Rule",
                "type": "THREAT",
                "updatedOn": "2021-12-08T17:17:56.504+00:00"
            },
            {
                "classification": null,
                "createdOn": "2021-10-26T22:33:17.567+00:00",
                "customerName": "Sample Customer",
                "destination": null,
                "detail": "ASC, MSTIC - Windows registry persistence method detected pqa VM_RegistryPersistencyKey",
                "id": "765432:THREAT:@AXy-u5fVt3G3ZYM6G5cH",
                "priority": 2,
                "severity": 2,
                "source": null,
                "status": {
                    "description": "False Positive"
                },
                "summary": "MS Graph Alert Detection Rule",
                "type": "THREAT",
                "updatedOn": "2021-12-16T17:21:31.384+00:00"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|classification|createdOn|customerName|destination|detail|id|priority|severity|source|status|summary|type|updatedOn|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 2021-09-17T16:26:11.731+00:00 | Sample Customer |  | MCAS - Impossible travel activity | 765432:THREAT:@AXv0k6GhG2zTcaogE1vG | 4 | 4 |  | description: Security Incident | MS Graph Alert Detection Rule | THREAT | 2021-12-08T17:17:56.504+00:00 |
>|  | 2021-10-26T22:33:17.567+00:00 | Sample Customer |  | ASC, MSTIC - Windows registry persistence method detected pqa VM_RegistryPersistencyKey | 765432:THREAT:@AXy-u5fVt3G3ZYM6G5cH | 2 | 2 |  | description: False Positive | MS Graph Alert Detection Rule | THREAT | 2021-12-16T17:21:31.384+00:00 |


### trustwave-get-finding
***
Get a Finding


#### Base Command

`trustwave-get-finding`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Finding ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trustwave.Finding.analystNotes.actor | String | User that created the analyst note. | 
| Trustwave.Finding.analystNotes.text | String | Analyst note text. | 
| Trustwave.Finding.analystNotes.timestamp | Date | Time when the note was created | 
| Trustwave.Finding.assetsIds | String | Assets impacted by the finding | 
| Trustwave.Finding.classification | String | Category for the finding | 
| Trustwave.Finding.createdOn | Date | Time when the finding was created. | 
| Trustwave.Finding.customerName | String | Customer name for the finding. | 
| Trustwave.Finding.destination | String | Destination for finding. | 
| Trustwave.Finding.detail | String | Detailed description of the finding. | 
| Trustwave.Finding.eventsIds | String | List of event ID associated with the finding. | 
| Trustwave.Finding.id | String | The finding ID | 
| Trustwave.Finding.parentId | String | The ID of the parent of the finding. | 
| Trustwave.Finding.priority | Number | The priority of the finding. | 
| Trustwave.Finding.severity | Number | The severity of the finding. | 
| Trustwave.Finding.source | String | Source for finding | 
| Trustwave.Finding.status.description | String | Current status of the Finding. | 
| Trustwave.Finding.summary | String | The name of the finding. | 
| Trustwave.Finding.type | String | The type of finding \(e.g. THREAT, VULNERABILITY\) | 
| Trustwave.Finding.updatedOn | Date | Time when the finding was last updated. | 

#### Command example
```!trustwave-get-finding id="765432:THREAT:@AXv0k6GhG2zTcaogE1vG"```
#### Context Example
```json
{
    "Trustwave": {
        "Finding": {
            "analystNotes": [
                {
                    "actor": "dummyuser",
                    "text": "Note A",
                    "timestamp": "2021-12-08T17:17:56.790+00:00"
                }
            ],
            "assetsIds": [
                "765432:PERSON:AXsNy0R8CfYgZQumlNdv"
            ],
            "childFindingIds": [],
            "classification": null,
            "createdOn": "2021-09-17T16:26:11.731+00:00",
            "customerName": "Sample Customer",
            "destination": null,
            "detail": "MCAS - Impossible travel activity",
            "eventsIds": [
                "34c0e1b2-96e6-4a25-be3d-80d0671a5d8f"
            ],
            "id": "765432:THREAT:@AXv0k6GhG2zTcaogE1vG",
            "parentId": null,
            "priority": 4,
            "severity": 4,
            "source": null,
            "status": {
                "description": "Security Incident"
            },
            "summary": "MS Graph Alert Detection Rule",
            "type": "THREAT",
            "updatedOn": "2021-12-08T17:17:56.504+00:00"
        }
    }
}
```

#### Human Readable Output

>### Results
>|analystNotes|assetsIds|childFindingIds|classification|createdOn|customerName|destination|detail|eventsIds|id|parentId|priority|severity|source|status|summary|type|updatedOn|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| {'actor': 'dummyuser', 'text': 'Note A', 'timestamp': '2021-12-08T17:17:56.790+00:00'} | 765432:PERSON:AXsNy0R8CfYgZQumlNdv |  |  | 2021-09-17T16:26:11.731+00:00 | Sample Customer |  | MCAS - Impossible travel activity | 34c0e1b2-96e6-4a25-be3d-80d0671a5d8f | 765432:THREAT:@AXv0k6GhG2zTcaogE1vG |  | 4 | 4 |  | description: Security Incident | MS Graph Alert Detection Rule | THREAT | 2021-12-08T17:17:56.504+00:00 |


### trustwave-get-asset
***
Get an Asset


#### Base Command

`trustwave-get-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Asset ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trustwave.Asset.cidr | String | Network address in CIDR notation. | 
| Trustwave.Asset.createdOn | Date | Time when the asset was created. | 
| Trustwave.Asset.customerName | String | The customer name for the asset. | 
| Trustwave.Asset.id | String | The asset ID. | 
| Trustwave.Asset.ips | String | List of IP addresses for the asset. | 
| Trustwave.Asset.lastActivity | Date | Time of the last activity associated with the asset. | 
| Trustwave.Asset.name | String | The name of the asset. | 
| Trustwave.Asset.networkInterfaces.gateway | String | Gateway address for the asset network interface. | 
| Trustwave.Asset.networkInterfaces.hostnames | String | List of hostname for the asset network interface | 
| Trustwave.Asset.networkInterfaces.ip | String | IP address for the asset network interface | 
| Trustwave.Asset.networkInterfaces.macAddress | String | MAC address for the asset network interface | 
| Trustwave.Asset.networkInterfaces.macVendor | String | Vendor associated with the MAC address for the asset network interface | 
| Trustwave.Asset.networkInterfaces.subnet | String | Network subnet the asset network interface | 
| Trustwave.Asset.os | String | Asset operating system. | 
| Trustwave.Asset.services.applicationName | String | Service name. | 
| Trustwave.Asset.services.applicationProtocol | String | Service protocol. | 
| Trustwave.Asset.services.port | Number | Service port | 
| Trustwave.Asset.services.transportProtocol | String | Service transport. | 
| Trustwave.Asset.status | String | Asset status. | 
| Trustwave.Asset.type | String | The type of asset. | 
| Trustwave.Asset.updatedOn | Date | Time when the asset was last updated. | 
| Trustwave.Asset.uri | String | URI of the asset. | 

#### Command example
```!trustwave-get-asset id="765432:DNA#DEVICE:AW2X-hCmXdgvNlcDpVGf"```
#### Context Example
```json
{
    "Trustwave": {
        "Asset": {
            "cidr": null,
            "createdOn": "2019-10-04T18:13:30.941+00:00",
            "customerName": "Sample Customer",
            "id": "765432:DNA#DEVICE:AW2X-hCmXdgvNlcDpVGf",
            "ips": [
                "10.103.201.47"
            ],
            "lastActivity": null,
            "name": "host.example.com",
            "networkInterfaces": [
                {
                    "gateway": null,
                    "hostnames": [
                        "host.example.com"
                    ],
                    "ip": "10.103.201.47",
                    "macAddress": null,
                    "macVendor": null,
                    "subnet": null
                }
            ],
            "notes": [],
            "os": null,
            "services": [
                {
                    "applicationName": null,
                    "applicationProtocol": null,
                    "port": 80,
                    "transportProtocol": "tcp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": "sunrpcportmap",
                    "port": 111,
                    "transportProtocol": "tcp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": "sunrpcportmap",
                    "port": 111,
                    "transportProtocol": "udp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": "ntp",
                    "port": 123,
                    "transportProtocol": "udp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": "snmp",
                    "port": 161,
                    "transportProtocol": "udp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": null,
                    "port": 443,
                    "transportProtocol": "tcp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": "mysql",
                    "port": 3306,
                    "transportProtocol": "tcp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": null,
                    "port": 5672,
                    "transportProtocol": "tcp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": "snmp",
                    "port": 16161,
                    "transportProtocol": "udp"
                }
            ],
            "status": null,
            "tags": [],
            "type": "Device",
            "updatedOn": "2019-10-04T19:09:59.907+00:00",
            "uri": null
        }
    }
}
```

#### Human Readable Output

>### Results
>|cidr|createdOn|customerName|id|ips|lastActivity|name|networkInterfaces|notes|os|services|status|tags|type|updatedOn|uri|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 2019-10-04T18:13:30.941+00:00 | Sample Customer | 765432:DNA#DEVICE:AW2X-hCmXdgvNlcDpVGf | 10.103.201.47 |  | host.example.com | {'gateway': None, 'hostnames': ['host.example.com'], 'ip': '10.103.201.47', 'macAddress': None, 'macVendor': None, 'subnet': None} |  |  | {'applicationName': None, 'applicationProtocol': None, 'port': 80, 'transportProtocol': 'tcp'},<br/>{'applicationName': None, 'applicationProtocol': 'sunrpcportmap', 'port': 111, 'transportProtocol': 'tcp'},<br/>{'applicationName': None, 'applicationProtocol': 'sunrpcportmap', 'port': 111, 'transportProtocol': 'udp'},<br/>{'applicationName': None, 'applicationProtocol': 'ntp', 'port': 123, 'transportProtocol': 'udp'},<br/>{'applicationName': None, 'applicationProtocol': 'snmp', 'port': 161, 'transportProtocol': 'udp'},<br/>{'applicationName': None, 'applicationProtocol': None, 'port': 443, 'transportProtocol': 'tcp'},<br/>{'applicationName': None, 'applicationProtocol': 'mysql', 'port': 3306, 'transportProtocol': 'tcp'},<br/>{'applicationName': None, 'applicationProtocol': None, 'port': 5672, 'transportProtocol': 'tcp'},<br/>{'applicationName': None, 'applicationProtocol': 'snmp', 'port': 16161, 'transportProtocol': 'udp'} |  |  | Device | 2019-10-04T19:09:59.907+00:00 |  |


### trustwave-search-assets
***
Search for Assets


#### Base Command

`trustwave-search-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Asset ID. | Optional | 
| limit | Maximum number of Assets to return. Default is 100. | Optional | 
| name | Name of the Asset. | Optional | 
| os | OS for the Asset. | Optional | 
| tags | Asset Tags to search for. | Optional | 
| port | port. | Optional | 
| app_protocol | Application Protocol. | Optional | 
| transport | Transport Protocol. | Optional | 
| type | Asset Type. | Optional | 
| created_since | created_since. | Optional | 
| updated_since | Updated since. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Trustwave.Asset.cidr | String | Network address in CIDR notation. | 
| Trustwave.Asset.createdOn | Date | Time when the asset was created. | 
| Trustwave.Asset.customerName | String | The customer name for the asset. | 
| Trustwave.Asset.id | String | The asset ID. | 
| Trustwave.Asset.ips | String | List of IP addresses for the asset. | 
| Trustwave.Asset.lastActivity | Date | Time of the last activity associated with the asset. | 
| Trustwave.Asset.name | String | The name of the asset. | 
| Trustwave.Asset.networkInterfaces.gateway | String | Gateway address for the asset network interface. | 
| Trustwave.Asset.networkInterfaces.hostnames | String | List of hostname for the asset network interface | 
| Trustwave.Asset.networkInterfaces.ip | String | IP address for the asset network interface | 
| Trustwave.Asset.networkInterfaces.macAddress | String | MAC address for the asset network interface | 
| Trustwave.Asset.networkInterfaces.macVendor | String | Vendor associated with the MAC address for the asset network interface | 
| Trustwave.Asset.networkInterfaces.subnet | String | Network subnet the asset network interface | 
| Trustwave.Asset.os | String | Asset operating system. | 
| Trustwave.Asset.status | String | Asset status. | 
| Trustwave.Asset.type | String | The type of asset. | 
| Trustwave.Asset.updatedOn | Date | Time when the asset was last updated. | 
| Trustwave.Asset.uri | String | URI of the asset. | 

#### Command example
```!trustwave-search-assets limit=2 type="DEVICE" name="host.example.com"```
#### Context Example
```json
{
    "Trustwave": {
        "Asset": {
            "cidr": null,
            "createdOn": "2019-10-04T18:13:30.941+00:00",
            "customerName": "Sample Customer",
            "id": "765432:DNA#DEVICE:AW2X-hCmXdgvNlcDpVGf",
            "ips": [
                "10.103.201.47"
            ],
            "lastActivity": null,
            "name": "host.example.com",
            "networkInterfaces": [
                {
                    "gateway": null,
                    "hostnames": [
                        "host.example.com"
                    ],
                    "ip": "10.103.201.47",
                    "macAddress": null,
                    "macVendor": null,
                    "subnet": null
                }
            ],
            "notes": [],
            "os": null,
            "services": [
                {
                    "applicationName": null,
                    "applicationProtocol": null,
                    "port": 80,
                    "transportProtocol": "tcp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": "sunrpcportmap",
                    "port": 111,
                    "transportProtocol": "tcp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": "sunrpcportmap",
                    "port": 111,
                    "transportProtocol": "udp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": "ntp",
                    "port": 123,
                    "transportProtocol": "udp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": "snmp",
                    "port": 161,
                    "transportProtocol": "udp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": null,
                    "port": 443,
                    "transportProtocol": "tcp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": "mysql",
                    "port": 3306,
                    "transportProtocol": "tcp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": null,
                    "port": 5672,
                    "transportProtocol": "tcp"
                },
                {
                    "applicationName": null,
                    "applicationProtocol": "snmp",
                    "port": 16161,
                    "transportProtocol": "udp"
                }
            ],
            "status": null,
            "tags": [],
            "type": "Device",
            "updatedOn": "2019-10-04T19:09:59.907+00:00",
            "uri": null
        }
    }
}
```

#### Human Readable Output

>### Results
>|cidr|createdOn|customerName|id|ips|lastActivity|name|networkInterfaces|notes|os|services|status|tags|type|updatedOn|uri|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 2019-10-04T18:13:30.941+00:00 | Sample Customer | 765432:DNA#DEVICE:AW2X-hCmXdgvNlcDpVGf | 10.103.201.47 |  | host.example.com | {'gateway': None, 'hostnames': ['host.example.com'], 'ip': '10.103.201.47', 'macAddress': None, 'macVendor': None, 'subnet': None} |  |  | {'applicationName': None, 'applicationProtocol': None, 'port': 80, 'transportProtocol': 'tcp'},<br/>{'applicationName': None, 'applicationProtocol': 'sunrpcportmap', 'port': 111, 'transportProtocol': 'tcp'},<br/>{'applicationName': None, 'applicationProtocol': 'sunrpcportmap', 'port': 111, 'transportProtocol': 'udp'},<br/>{'applicationName': None, 'applicationProtocol': 'ntp', 'port': 123, 'transportProtocol': 'udp'},<br/>{'applicationName': None, 'applicationProtocol': 'snmp', 'port': 161, 'transportProtocol': 'udp'},<br/>{'applicationName': None, 'applicationProtocol': None, 'port': 443, 'transportProtocol': 'tcp'},<br/>{'applicationName': None, 'applicationProtocol': 'mysql', 'port': 3306, 'transportProtocol': 'tcp'},<br/>{'applicationName': None, 'applicationProtocol': None, 'port': 5672, 'transportProtocol': 'tcp'},<br/>{'applicationName': None, 'applicationProtocol': 'snmp', 'port': 16161, 'transportProtocol': 'udp'} |  |  | Device | 2019-10-04T19:09:59.907+00:00 |  |
