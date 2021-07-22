KnowBE4 PhishER integration allows to pull events from PhishER system and do mutations
This integration was integrated and tested on July 20201.

## Configure Phisher on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Phisher.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL | Server's URL | True |
    | API Key |  | True |
    | Trust any certificate (not secure) |  | False |
    | First Fetch Time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
    | Fetch incidents |  | False |
    | Incidents Fetch Interval |  | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### phisher-message-list
***
Command to get messages from PhishER


#### Base Command

`phisher-message-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | number of maximum events to fetch, default value 200. Default is 200. | Optional | 
| query | The Lucene query to search against. | Optional | 
| id | id of specific event to get only specific event. if ID is entered it overides the value given to query. | Optional | 
| include_events | false - will not write all event information to context. true - will write all events to context. Possible values are: False, True. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Phisher.Message.actionStatus | String | Action Status | 
| Phisher.Message.attachments | String | a collection of attachments associated with this message | 
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
``` ```
!phisher-message-list
will bring all events to the context
!phisher-message-list include_events=True
will bring all events and the related event history
!phisher-message-list id=cff35e34-aeb6-4263-b592-c68fc03ea7cb
will bring specific event
!

### phisher-create-comment
***
Adds a comment to a PhishER message


#### Base Command

`phisher-create-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of message. | Required | 
| comment | the comment to be added. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```
!phisher-create-comment id=cff35e34-aeb6-4263-b592-c68fc03ea7cb comment="My current update"

### phisher-update-message-status
***
Updates a PhishER message status, user must provide at least one of the parameters


#### Base Command

`phisher-update-message-status`
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
``` ```
!phisher-update-message-status id=cff35e34-aeb6-4263-b592-c68fc03ea7cb category=CLEAN severity=HIGH status=RESOLVED


### phisher-create-tags
***
command that creates tags for specific message


#### Base Command

`phisher-create-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Message ID. | Required | 
| tags | Message Tags to assign for given ID. Tags should be seperated by a comma. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```
!phisher-create-tags id=edd66fed-5150-4a73-b447-6572987c7392 tags="tag1, tag2"

### phisher-delete-tags
***
command that deletes tags to a specified message


#### Base Command

`phisher-delete-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Message ID. | Required | 
| tags | Message Tags to delete for given ID. Tags should be seperated by a comma. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```
!phisher-delete-tags id=edd66fed-5150-4a73-b447-6572987c7392 tags="tag1"


