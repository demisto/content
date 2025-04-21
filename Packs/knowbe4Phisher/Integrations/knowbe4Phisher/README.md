**KnowBe4 PhishER** integration allows to pull events from PhishER system and do mutations.
This integration was integrated and tested with version 6.0.0 of XSOAR

## Configure Phisher in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| API Key |  | True |
| First Fetch Time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| Fetch incidents |  | False |
| Fetch Limit | Maximum number of alerts per fetch. Default is 50, maximum is 100. | False |
| Incident type |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### phisher-message-list
***
Command to get messages from PhishER


#### Base Command

`phisher-message-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of messages to fetch. Default is 50. | Optional | 
| query | The Lucene query to search against. | Optional | 
| id | ID of specific message to retrieve. If ID is given query will be ignored. | Optional | 
| include_events | Whether to include all message events in the result. Possible values are: False, True. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Phisher.Message.actionStatus | String | Action Status | 
| Phisher.Message.attachments | String | A collection of attachments associated with this message | 
| Phisher.Message.category | String | The message's category | 
| Phisher.Message.comments | String | A collection of comments associated with this message. | 
| Phisher.Message.events | String | A collection of events associated with this message. | 
| Phisher.Message.from | String | Sender's email | 
| Phisher.Message.id | String | Unique identifier for the message. | 
| Phisher.Message.links | String | A collection of links that were found in the message. | 
| Phisher.Message.phishmlReport | String | The PhishML report associated with this message | 
| Phisher.Message.pipelineStatus | String | Pipeline Status | 
| Phisher.Message.reportedBy | String | The person who reported the message. | 
| Phisher.Message.rawUrl | String | URL where to download the raw message | 
| Phisher.Message.rules | String | A collection of rules associated with this message. | 
| Phisher.Message.severity | String | The message's severity | 
| Phisher.Message.subject | String | Subject of the message. | 
| Phisher.Message.tags | String | A collection of tags associated with this message. | 


#### Command Example
```!phisher-message-list id=00a43d65-5802-4df6-9c3c-f7d2024ddb0b```

#### Context Example
```json
{
    "Phisher": {
        "Message": {
            "actionStatus": "IN_REVIEW",
            "attachments": [],
            "category": "CLEAN",
            "comments": [
                {
                    "body": "Folarin Balogun",
                    "createdAt": "2021-08-17T14:43:22Z"
                },
                {
                    "body": "Emile Smith Rowe 10",
                    "createdAt": "2021-08-17T14:21:17Z"
                },
                {
                    "body": "Emile Smith Rowe",
                    "createdAt": "2021-08-17T14:20:32Z"
                },
                {
                    "body": "Chupi & Toto",
                    "createdAt": "2021-08-16T12:39:15Z"
                }
            ],
            "created at": "2021-07-07T15:18:58+00:00",
            "from": "ekatsenelson@paloaltonetworks.com",
            "id": "00a43d65-5802-4df6-9c3c-f7d2024ddb0b",
            "links":[],
            "phishmlReport": null,
            "pipelineStatus": "PROCESSED",
            "rawUrl": "https://phisher.example.com",
            "reportedBy": "ekatsenelson@paloaltonetworks.com",
            "rules": [],
            "severity": "MEDIUM",
            "subject": "Fwd: Your next career opportunity is... Right Here!",
            "tags": [
                {
                    "name": "SIA",
                    "type": "STANDARD"
                },
                {
                    "name": "DAVY KLAASEN",
                    "type": "STANDARD"
                },
                {
                    "name": "DUSAN TADIC",
                    "type": "STANDARD"
                },
                {
                    "name": "LENO",
                    "type": "STANDARD"
                },
                {
                    "name": "BALOGUN",
                    "type": "STANDARD"
                },
                {
                    "name": "RYAN GRAVENBERGH",
                    "type": "STANDARD"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Messages
>|ID|Status|Category|From|Severity|Created At|
>|---|---|---|---|---|---|
>| 00a43d65-5802-4df6-9c3c-f7d2024ddb0b | IN_REVIEW | CLEAN | ekatsenelson@paloaltonetworks.com | MEDIUM | 2021-07-07T15:18:58+00:00 |


### phisher-create-comment
***
Adds a comment to a PhishER message


#### Base Command

`phisher-create-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Message ID. | Required | 
| comment | The comment to add. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!phisher-create-comment id=00a43d65-5802-4df6-9c3c-f7d2024ddb0b comment="Test Comment"```

#### Human Readable Output

>The comment was added successfully

### phisher-update-message
***
Updates a PhishER message status. User must provide at least one argument.


#### Base Command

`phisher-update-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | Message Category, can be: UNKNOWN,CLEAN,SPAM,THREAT		. Possible values are: UNKNOWN, CLEAN, SPAM, THREAT. | Optional | 
| status | Message Status, can be: RECEIVED,IN_REVIEW,RESOLVED. Possible values are: RECEIVED, IN_REVIEW, RESOLVED. | Optional | 
| severity | Message Severity, can be: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL. Possible values are: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL. | Optional | 
| id | Message ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!phisher-update-message id=00a43d65-5802-4df6-9c3c-f7d2024ddb0b category=THREAT severity=MEDIUM status=IN_REVIEW```

#### Human Readable Output

>The message was updated successfully

### phisher-tags-create
***
Add tags to a given message


#### Base Command

`phisher-tags-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Message ID. | Required | 
| tags | Comma separated list of tags to add. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!phisher-tags-create id=00a43d65-5802-4df6-9c3c-f7d2024ddb0b tags="Tag1, Tag2"```

#### Human Readable Output

>The tags were updated successfully

### phisher-tags-delete
***
Removes tags from a given message.


#### Base Command

`phisher-tags-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Message ID. | Required | 
| tags | Comma separated list of tags to remove. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!phisher-tags-delete id=00a43d65-5802-4df6-9c3c-f7d2024ddb0b tags="Tag2"```

#### Human Readable Output

>The tags were deleted successfully