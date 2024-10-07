Google Cloud Pub / Sub is a fully-managed real-time messaging service that allows you to send and receive messages between independent applications.
This integration was integrated and tested with Google Cloud Pub/Sub

## Required Permissions

To use this integration you must have a Service Account with one of the following roles:
- **Project-Owner**
- **Project-Editor**
- **Pub/Sub Admin**
- **Pub/Sub Editor**

## Known Limitations
When clicking on **Reset the "last run" timestamp**, messages that were recently pulled (including pulls via classification mapper) might take a few minutes before they can be fetched again.
Because the fetch ignores older messages once newer ones were fetched, it's recommended to wait a few minutes following a reset before trying to fetch again, to prevent older messages from being dropped.

## Configure GooglePubSub in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| service_account_json | Service Account Private Key File Contents \(JSON\) | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| default_subscription | Fetch Incidents Subscription ID | False |
| default_project | Fetch Incidents Project ID | False |
| default_max_msgs | Max Incidents Per Fetch | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gcp-pubsub-topics-list
***
Get a list of the project's topics.


##### Base Command

`gcp-pubsub-topics-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | ID of the project to look in. | Optional | 
| page_size | Max amount of entries to get. | Optional | 
| page_token | Next page token as returned from &quot;gcp-pubsub-topics-list&quot; command | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudPubSubTopics.name | String | Name of the topic | 
| GoogleCloudPubSub.Topics.nextPageToken | String | If not empty, indicates that there may be more topics that match the request. | 


##### Command Example
```!gcp-pubsub-topics-list project_id=dmst-integrations```

##### Context Example
```
{
    "GoogleCloudPubSubTopics": {
        "name": "projects/dmst-integrations/topics/dmst-topic"
    }
}
```

##### Human Readable Output
### Topics for project dmst-integrations
|name|
|---|
| projects/dmst-integrations/topics/dmst-topic |


### gcp-pubsub-topic-publish-message
***
Publish a message in a topic.


##### Base Command

`gcp-pubsub-topic-publish-message`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic_id | ID of the topic e.g. &quot;projects/{project_id}/topics/topic_id&quot;. | Required | 
| data | The message data field. If this field is empty, the message must contain at least one attribute. | Optional | 
| attributes | Attributes for this message. If this field is empty, the message must contain non-empty data. Input format: &quot;key=val&quot; pairs sepearated by &quot;,&quot;. | Optional | 
| project_id | Project ID. | Optional | 
| delim_char_attributes | Set delimiter of attributes split. | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudPubSubPublishedMessages.messageId | String | ID of the published message | 
| GoogleCloudPubSubPublishedMessages.topic | String | Topic of the published message | 
| GoogleCloudPubSubPublishedMessages.data | String | Text data of the published message. | 
| GoogleCloudPubSubPublishedMessages.attributes | Unknown | The message attributes. | 


##### Command Example
```!gcp-pubsub-topic-publish-message data="42 is the answer" project_id=dmst-integrations topic_id=dmst-topic delim_char_attributes=","```

##### Context Example
```
{
    "GoogleCloudPubSubPublishedMessages": {
        "attributes": null,
        "data": "42 is the answer",
        "messageId": "874663628353499",
        "topic": "dmst-topic",
        "delim_char_attributes": ","
    }
}
```

##### Human Readable Output
### Google Cloud PubSub has published the message successfully
|Data|Message Id|Topic|
|---|---|---|
| 42 is the answer | 874663628353499 | dmst-topic |


### gcp-pubsub-topic-subscription-get-by-name
***
Get subscription details by subscription ID.


##### Base Command

`gcp-pubsub-topic-subscription-get-by-name`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | ID of the project from which the subscription is receiving messages. | Optional | 
| subscription_id | ID of the subscription, without project/topic prefix. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudPubSubSubscriptions.ackDeadlineSeconds | Number | The amount of time Pub/Sub waits for the subscriber to acknowledge receipt before resending the message. | 
| GoogleCloudPubSubSubscriptions.expirationPolicy.ttl | String | The &quot;time\-to\-live&quot; duration for the subscription. | 
| GoogleCloudPubSubSubscriptions.messageRetentionDuration | String | How long to retain unacknowledged messages in the subscription&\#x27;s backlog | 
| GoogleCloudPubSubSubscriptions.name | String | Name of the subscription | 
| GoogleCloudPubSubSubscriptions.topic | String | Name of the topic from which the subscription is receiving messages | 


##### Command Example
```!gcp-pubsub-topic-subscription-get-by-name subscription_id=test_sub_2 project_id=dmst-integrations```

##### Context Example
```
{
    "GoogleCloudPubSubSubscriptions": {
        "ackDeadlineSeconds": 10,
        "expirationPolicy": {
            "ttl": "9999999999s"
        },
        "messageRetentionDuration": "604800s",
        "name": "projects/dmst-integrations/subscriptions/test_sub_2",
        "pushConfig": {},
        "topic": "projects/dmst-integrations/topics/dmst-topic"
    }
}
```

##### Human Readable Output
### Subscription test_sub_2
|ackDeadlineSeconds|expirationPolicy|messageRetentionDuration|name|pushConfig|topic|
|---|---|---|---|---|---|
| 10 | ttl: 9999999999s | 604800s | projects/dmst-integrations/subscriptions/test_sub_2 |  | projects/dmst-integrations/topics/dmst-topic |


### gcp-pubsub-topic-subscriptions-list
***
Get a list of subscriptions by project ID or topic ID.


##### Base Command

`gcp-pubsub-topic-subscriptions-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | ID of the project from which the subscription is receiving messages. | Optional | 
| topic_id | ID of the topic from which the subscription is receiving messages. | Optional | 
| page_size | Max number of results | Optional | 
| page_token | Next page token as returned from the API. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudPubSubSubscriptions.ackDeadlineSeconds | Number | The amount of time Pub/Sub waits for the subscriber to acknowledge receipt before resending the message. | 
| GoogleCloudPubSubSubscriptions.expirationPolicy.ttl | String | The &quot;time\-to\-live&quot; duration for the subscription | 
| GoogleCloudPubSubSubscriptions.messageRetentionDuration | String | How long to retain unacknowledged messages in the subscription&\#x27;s backlog | 
| GoogleCloudPubSubSubscriptions.name | String | Name of the subscription | 
| GoogleCloudPubSubSubscriptions.topic | String | Name of the topic from which the subscription is receiving messages. | 
| GoogleCloudPubSubSubscriptions.pushConfig.pushEndpoint | String | A URL locating the endpoint to which messages should be pushed. | 
| c | Unknown | If not empty, indicates that there may be more snapshot that match the request. | 


##### Command Example
```!gcp-pubsub-topic-subscriptions-list project_id=dmst-integrations```

##### Context Example
```
{
    "GoogleCloudPubSubSubscriptions": [
        {
            "ackDeadlineSeconds": 11,
            "expirationPolicy": {
                "ttl": "2678400s"
            },
            "messageRetentionDuration": "604800s",
            "name": "projects/dmst-integrations/subscriptions/dean-sub1",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "2678400s"
            },
            "messageRetentionDuration": "604800s",
            "name": "projects/dmst-integrations/subscriptions/dean-sub2",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "22678400s"
            },
            "messageRetentionDuration": "604800s",
            "name": "projects/dmst-integrations/subscriptions/test_sub_1",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "2678400s"
            },
            "messageRetentionDuration": "604800s",
            "name": "projects/dmst-integrations/subscriptions/test_sub",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "9999999999s"
            },
            "messageRetentionDuration": "604800s",
            "name": "projects/dmst-integrations/subscriptions/test_sub_2",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "86400s"
            },
            "messageRetentionDuration": "86400s",
            "name": "projects/dmst-integrations/subscriptions/test_sub_1587031883059",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "86400s"
            },
            "labels": {
                "test": "true"
            },
            "messageRetentionDuration": "86400s",
            "name": "projects/dmst-integrations/subscriptions/test_sub_1587032827289",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "86400s"
            },
            "labels": {
                "test": "true"
            },
            "messageRetentionDuration": "86400s",
            "name": "projects/dmst-integrations/subscriptions/test_sub_1587039285961",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "86400s"
            },
            "labels": {
                "test": "true"
            },
            "messageRetentionDuration": "86400s",
            "name": "projects/dmst-integrations/subscriptions/test_sub_1587038878685",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "86400s"
            },
            "labels": {
                "test": "true"
            },
            "messageRetentionDuration": "86400s",
            "name": "projects/dmst-integrations/subscriptions/test_sub_1587039587203",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "86400s"
            },
            "labels": {
                "test": "true"
            },
            "messageRetentionDuration": "86400s",
            "name": "projects/dmst-integrations/subscriptions/test_sub_1587040075117",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "86400s"
            },
            "labels": {
                "test": "true"
            },
            "messageRetentionDuration": "86400s",
            "name": "projects/dmst-integrations/subscriptions/test_sub_1587042146495",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "86400s"
            },
            "labels": {
                "test": "true"
            },
            "messageRetentionDuration": "86400s",
            "name": "projects/dmst-integrations/subscriptions/test_sub_1587043084505",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 10,
            "expirationPolicy": {
                "ttl": "86400s"
            },
            "labels": {
                "doc": "true"
            },
            "messageRetentionDuration": "86400s",
            "name": "projects/dmst-integrations/subscriptions/doc_sub",
            "pushConfig": {},
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        },
        {
            "ackDeadlineSeconds": 600,
            "expirationPolicy": {},
            "messageRetentionDuration": "604800s",
            "name": "projects/dmst-integrations/subscriptions/gcf-function-1-us-central1-dmst-topic",
            "pushConfig": {
                "attributes": {
                    "x-goog-version": "v1"
                },
                "pushEndpoint": "https://d4d1290519676f29baf13a7bf18a25bf-dot-j40fd5d18d8c290e1p-tp.appspot.com/_ah/push-handlers/pubsub/projects/dmst-integrations/topics/dmst-topic?pubsub_trigger=true"
            },
            "topic": "projects/dmst-integrations/topics/dmst-topic"
        }
    ]
}
```

##### Human Readable Output
### Subscriptions in project dmst-integrations
|Name|Topic|Ack Deadline Seconds|Labels|
|---|---|---|---|
| projects/dmst-integrations/subscriptions/dean-sub1 | projects/dmst-integrations/topics/dmst-topic | 11 |  |
| projects/dmst-integrations/subscriptions/dean-sub2 | projects/dmst-integrations/topics/dmst-topic | 10 |  |
| projects/dmst-integrations/subscriptions/test_sub_1 | projects/dmst-integrations/topics/dmst-topic | 10 |  |
| projects/dmst-integrations/subscriptions/test_sub | projects/dmst-integrations/topics/dmst-topic | 10 |  |
| projects/dmst-integrations/subscriptions/test_sub_2 | projects/dmst-integrations/topics/dmst-topic | 10 |  |
| projects/dmst-integrations/subscriptions/test_sub_1587031883059 | projects/dmst-integrations/topics/dmst-topic | 10 |  |
| projects/dmst-integrations/subscriptions/test_sub_1587032827289 | projects/dmst-integrations/topics/dmst-topic | 10 | test: true |
| projects/dmst-integrations/subscriptions/test_sub_1587039285961 | projects/dmst-integrations/topics/dmst-topic | 10 | test: true |
| projects/dmst-integrations/subscriptions/test_sub_1587038878685 | projects/dmst-integrations/topics/dmst-topic | 10 | test: true |
| projects/dmst-integrations/subscriptions/test_sub_1587039587203 | projects/dmst-integrations/topics/dmst-topic | 10 | test: true |
| projects/dmst-integrations/subscriptions/test_sub_1587040075117 | projects/dmst-integrations/topics/dmst-topic | 10 | test: true |
| projects/dmst-integrations/subscriptions/test_sub_1587042146495 | projects/dmst-integrations/topics/dmst-topic | 10 | test: true |
| projects/dmst-integrations/subscriptions/test_sub_1587043084505 | projects/dmst-integrations/topics/dmst-topic | 10 | test: true |
| projects/dmst-integrations/subscriptions/doc_sub | projects/dmst-integrations/topics/dmst-topic | 10 | doc: true |
| projects/dmst-integrations/subscriptions/gcf-function-1-us-central1-dmst-topic | projects/dmst-integrations/topics/dmst-topic | 600 |  |


### gcp-pubsub-topic-messages-pull
***
Pull messages that were published.


##### Base Command

`gcp-pubsub-topic-messages-pull`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Project ID to pull messages from. | Optional | 
| subscription_id | Subscription ID to pull messages from. | Required | 
| max_messages | The maximum number of messages to return for this request. Must be a positive integer. | Optional | 
| ack | Acknowledge the messages pulled. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudPubSubPulledMessages.data | String | Text data of the pulled message. | 
| GoogleCloudPubSubPulledMessages.messageId | String | ID of the message | 
| GoogleCloudPubSubPulledMessages.publishTime | Date | The time the message was published | 
| GoogleCloudPubSubPulledMessages.attributes | Unknown | The message attributes. | 


##### Command Example
```!gcp-pubsub-topic-messages-pull ack=true max_messages=1 project_id=dmst-integrations subscription_id=test_sub_2```

##### Context Example
```
{
    "GoogleCloudPubSubPulledMessages": {
        "data": "42 is the answer",
        "messageId": "874662740221427",
        "publishTime": "2020-04-16T13:32:41.398Z"
    }
}
```

##### Human Readable Output
### Google Cloud PubSub Messages
|data|messageId|publishTime|
|---|---|---|
| 42 is the answer | 874662740221427 | 2020-04-16T13:32:41.398Z |


### gcp-pubsub-topic-subscription-create
***
Create a pull or push subscription.


##### Base Command

`gcp-pubsub-topic-subscription-create`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | ID of the project from which the subscription is receiving messages. | Optional | 
| subscription_id | ID of the created subscription. | Required | 
| topic_id | ID of the topic from which the subscription is receiving messages. | Required | 
| push_endpoint | A URL locating the endpoint to which messages should be pushed. | Optional | 
| push_attributes | Endpoint configuration attributes that can be used to control the message delivery, such as &quot;x-goog-version&quot;, which you can use to change the format of the pushed message. Input format: &quot;key=val&quot; pairs sepearated by &quot;,&quot;. | Optional | 
| ack_deadline_seconds | The amount of time Pub/Sub waits for the subscriber to acknowledge receipt before resending the message. | Optional | 
| retain_acked_messages | Indicates whether to retain acknowledged messages. | Optional | 
| message_retention_duration | How long to retain unacknowledged messages in the subscription&#x27;s backlog. A duration of seconds e.g. &quot;4.2s&quot; | Optional | 
| labels | Input format: &quot;key=val&quot; pairs sepearated by &quot;,&quot;. | Optional | 
| expiration_ttl | The &quot;time-to-live&quot; duration for the subscription. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudPubSubSubscriptions.ackDeadlineSeconds | Number | The amount of time Pub/Sub waits for the subscriber to acknowledge receipt before resending the message. | 
| GoogleCloudPubSubSubscriptions.expirationPolicy.ttl | String | The &quot;time\-to\-live&quot; duration for the subscription. | 
| GoogleCloudPubSubSubscriptions.messageRetentionDuration | String | How long to retain unacknowledged messages in the subscription&\#x27;s backlog | 
| GoogleCloudPubSubSubscriptions.name | String | Name of the subscription | 
| GoogleCloudPubSubSubscriptions.topic | String | Name of the topic from which the subscription is receiving messages | 
| GoogleCloudPubSubSubscriptions.projectName | String | Name of the project from which the subscription is receiving messages | 
| GoogleCloudPubSubSubscriptions.subscriptionName | String | Name of the newly created subscription | 
| GoogleCloudPubSubSubscriptions.labels | String | An object containing a list of &quot;key&quot;: value pairs. | 


##### Command Example
```!gcp-pubsub-topic-subscription-create expiration_ttl=86400s project_id=dmst-integrations topic_id=dmst-topic subscription_id=doc_sub_1```

##### Context Example
```
{
    "GoogleCloudPubSubSubscriptions": {
        "ackDeadlineSeconds": 10,
        "expirationPolicy": {
            "ttl": "86400s"
        },
        "messageRetentionDuration": "86400s",
        "name": "projects/dmst-integrations/subscriptions/doc_sub_1",
        "projectName": "dmst-integrations",
        "pushConfig": {},
        "subscriptionName": "doc_sub_1",
        "topic": "projects/dmst-integrations/topics/dmst-topic"
    }
}
```

##### Human Readable Output
### Subscription doc_sub_1 was created successfully
|ackDeadlineSeconds|expirationPolicy|messageRetentionDuration|name|pushConfig|topic|
|---|---|---|---|---|---|
| 10 | ttl: 86400s | 86400s | projects/dmst-integrations/subscriptions/doc_sub_1 |  | projects/dmst-integrations/topics/dmst-topic |


### gcp-pubsub-topic-create
***
Create a topic.


##### Base Command

`gcp-pubsub-topic-create`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | ID of the project the topic will belong to. | Optional | 
| topic_id | ID of the newly created topic. | Required | 
| labels | &#x27;Input format: &quot;key=val&quot; pairs sepearated by &quot;,&quot;.&#x27; | Optional | 
| allowed_persistence_regions | A comma separated list of IDs of GCP regions where messages that are published to the topic may be persisted in storage. e.g. &quot;us-east4,asia-1&quot;.<br/>https://cloud.google.com/compute/docs/regions-zones#locations | Optional | 
| kms_key_name | The full name of the Cloud KMS CryptoKey to be used to restrict access to messages published on this topic.<br/><br/>Full name format: projects/*/locations/*/keyRings/*/cryptoKeys/*. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudPubSubTopics.name | String | Name of the topic | 
| GoogleCloudPubSubTopics.labels | Unknown | An object containing a list of &quot;key&quot;: value pairs. | 
| GoogleCloudPubSubTopics.messageStoragePolicy.allowedPersistenceRegions | Unknown | A list of IDs of GCP regions where messages that are published to the topic may be persisted in storage. | 
| GoogleCloudPubSubTopics.kmsKeyName | String | The resource name of the Cloud KMS CryptoKey to be used to restrict access. | 


##### Command Example
```!gcp-pubsub-topic-create project_id=dmst-integrations topic_id=dmst-doc-topic```

##### Context Example
```
{
    "GoogleCloudPubSubTopics": {
        "name": "projects/dmst-integrations/topics/dmst-doc-topic"
    }
}
```

##### Human Readable Output
### Topic **dmst-doc-topic** was created successfully
|Name|
|---|
| projects/dmst-integrations/topics/dmst-doc-topic |


### gcp-pubsub-topic-delete
***
Delete a topic.


##### Base Command

`gcp-pubsub-topic-delete`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | ID of the project the topic will belong to. | Optional | 
| topic_id | ID of the newly created topic. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!gcp-pubsub-topic-delete project_id=dmst-integrations topic_id=dmst-doc-topic```

##### Context Example
```
{}
```

##### Human Readable Output
Topic **dmst-doc-topic** was deleted successfully

### gcp-pubsub-topic-update
***
Updates a topic.


##### Base Command

`gcp-pubsub-topic-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | ID of the project the topic belongs to. | Optional | 
| topic_id | ID of the topic. | Required | 
| labels | &#x27;Input format: &quot;key=val&quot; pairs sepearated by &quot;,&quot;.&#x27; | Optional | 
| allowed_persistence_regions | A comma separated list of IDs of GCP regions where messages that are published to the topic may be persisted in storage. e.g. &quot;us-east4,asia-1&quot;.<br/>https://cloud.google.com/compute/docs/regions-zones#locations | Optional | 
| kms_key_name | The full name of the Cloud KMS CryptoKey to be used to restrict access to messages published on this topic.<br/><br/>Full name format: projects/*/locations/*/keyRings/*/cryptoKeys/*. | Optional | 
| update_mask | Indicates which fields in the provided topic to update.<br/>A comma-separated list of fields. Example: &quot;labels,messageStoragePolicy&quot;. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudPubSubTopics.name | String | Name of the topic | 
| GoogleCloudPubSubTopics.labels | Unknown | An object containing a list of &quot;key&quot;: value pairs. | 
| GoogleCloudPubSubTopics.messageStoragePolicy.allowedPersistenceRegions | Unknown | A list of IDs of GCP regions where messages that are published to the topic may be persisted in storage. | 
| GoogleCloudPubSubTopics.kmsKeyName | String | The resource name of the Cloud KMS CryptoKey to be used to restrict access. | 


##### Command Example
```!gcp-pubsub-topic-update project_id=dmst-integrations topic_id=dmst-doc-topic labels="doc=true" update_mask=labels```

##### Context Example
```
{
    "GoogleCloudPubSubTopics": {
        "labels": {
            "doc": "true"
        },
        "name": "projects/dmst-integrations/topics/dmst-doc-topic"
    }
}
```

##### Human Readable Output
### Topic dmst-doc-topic was updated successfully
|Labels|Name|
|---|---|
| doc: true | projects/dmst-integrations/topics/dmst-doc-topic |


### gcp-pubsub-topic-subscription-update
***
Update a subscription.


##### Base Command

`gcp-pubsub-topic-subscription-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| update_mask | Indicates which fields in the provided subscription to update.<br/>A comma-separated list of fully qualified names of fields.<br/>Example: &quot;pushConfig.pushEndpoint,ackDeadlineSeconds&quot;. | Required | 
| project_id | ID of the project from which the subscription is receiving messages. | Optional | 
| subscription_id | ID of the updated subscription. | Required | 
| topic_id | ID of the topic from which the subscription is receiving messages. | Required | 
| push_endpoint | A URL locating the endpoint to which messages should be pushed. | Optional | 
| push_attributes | Endpoint configuration attributes that can be used to control the message delivery. Input format: &quot;key=val&quot; pairs sepearated by &quot;,&quot;. | Optional | 
| ack_deadline_seconds | The amount of time Pub/Sub waits for the subscriber to acknowledge receipt before resending the message. | Optional | 
| retain_acked_messages | Indicates whether to retain acknowledged messages. | Optional | 
| message_retention_duration | How long to retain unacknowledged messages in the subscription&#x27;s backlog. A duration of seconds e.g. &quot;4.2s&quot; | Optional | 
| labels | Input format: &quot;key=val&quot; pairs sepearated by &quot;,&quot;. | Optional | 
| expiration_ttl | The &quot;time-to-live&quot; duration for the subscription. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudPubSubSubscriptions.ackDeadlineSeconds | Number | The amount of time Pub/Sub waits for the subscriber to acknowledge receipt before resending the message. | 
| GoogleCloudPubSubSubscriptions.expirationPolicy.ttl | String | The &quot;time\-to\-live&quot; duration for the subscription. | 
| GoogleCloudPubSubSubscriptions.messageRetentionDuration | String | How long to retain unacknowledged messages in the subscription&\#x27;s backlog. | 
| GoogleCloudPubSubSubscriptions.name | String | Name of the subscription. | 
| GoogleCloudPubSubSubscriptions.topic | String | Name of the topic from which the subscription is receiving messages. | 
| GoogleCloudPubSubSubscriptions.projectName | String | Name of the project from which the subscription is receiving messages. | 
| GoogleCloudPubSubSubscriptions.subscriptionName | String | Name of the subscription. | 
| GoogleCloudPubSubSubscriptions.labels | String | An object containing a list of &quot;key&quot;: value pairs. | 


##### Command Example
```!gcp-pubsub-topic-subscription-update labels="doc=true" project_id=dmst-integrations subscription_id=doc_sub_1 topic_id=dmst-topic update_mask=labels```

##### Context Example
```
{
    "GoogleCloudPubSubSubscriptions": {
        "ackDeadlineSeconds": 10,
        "expirationPolicy": {
            "ttl": "86400s"
        },
        "labels": {
            "doc": "true"
        },
        "messageRetentionDuration": "86400s",
        "name": "projects/dmst-integrations/subscriptions/doc_sub_1",
        "projectName": "dmst-integrations",
        "pushConfig": {
            "attributes": {
                "x-goog-version": "v1"
            }
        },
        "subscriptionName": "doc_sub_1",
        "topic": "projects/dmst-integrations/topics/dmst-topic"
    }
}
```

##### Human Readable Output
### Subscription doc_sub_1 was updated successfully
|ackDeadlineSeconds|expirationPolicy|labels|messageRetentionDuration|name|pushConfig|topic|
|---|---|---|---|---|---|---|
| 10 | ttl: 86400s | doc: true | 86400s | projects/dmst-integrations/subscriptions/doc_sub_1 | attributes: {"x-goog-version": "v1"} | projects/dmst-integrations/topics/dmst-topic |


### gcp-pubsub-topic-messages-seek
***
Seeks a subscription to a given point in time or to a given snapshot.


##### Base Command

`gcp-pubsub-topic-messages-seek`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | ID of the project from which the subscription is receiving messages. | Optional | 
| subscription_id | ID of the subscription, without project/topic prefix. | Required | 
| time_string | A timestamp in RFC3339 UTC &quot;Zulu&quot; format, accurate to nanoseconds. Example: &quot;2014-10-02T15:01:23.045123456Z&quot;. | Optional | 
| snapshot | The snapshot to seek to. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!gcp-pubsub-topic-messages-seek time_string="2020-04-16T13:27:55.117Z" project_id=dmst-integrations topic_id=dmst-topic subscription_id=doc_sub_1```

##### Context Example
```
{}
```

##### Human Readable Output
Message seek was successful for **time: 2020-04-16T13:27:55.117Z**

### gcp-pubsub-topic-snapshots-list
***
Get a list of snapshots by project ID and topic ID.


##### Base Command

`gcp-pubsub-topic-snapshots-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The ID of the project from which this snapshot is retaining messages. | Optional | 
| topic_id | The ID of the topic from which this snapshot is retaining messages. | Optional | 
| page_size | Max number of results | Optional | 
| page_token | Next page token as returned from the API. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudPubSubSnapshots.name | String | The name of the snapshot. | 
| GoogleCloudPubSubSnapshots.topic | Unknown | The name of the topic from which this snapshot is retaining messages. | 
| GoogleCloudPubSubSnapshots.expireTime | Date | The snapshot is guaranteed to exist up until this time. | 
| GoogleCloudPubSubSnapshots.labels | Unknown | An object containing a list of &quot;key&quot;: value pairs. | 
| GoogleCloudPubSub.Snapshots.nextPageToken | String | If not empty, indicates that there may be more snapshot that match the request. | 


##### Command Example
```!gcp-pubsub-topic-snapshots-list project_id=dmst-integrations```

##### Context Example
```
{
    "GoogleCloudPubSubSnapshots": {
        "expireTime": "2020-04-23T13:37:26.199Z",
        "labels": {
            "doc": "true"
        },
        "name": "projects/dmst-integrations/snapshots/doc_snapshot",
        "topic": "projects/dmst-integrations/topics/dmst-topic"
    }
}
```

##### Human Readable Output
### Snapshots for project dmst-integrations
|name|
|---|
| projects/dmst-integrations/snapshots/doc_snapshot |


### gcp-pubsub-topic-snapshot-create
***
Creates a snapshot from the requested subscription. Snapshots are used in gcp-pubsub-topic-messages-seek command.


##### Base Command

`gcp-pubsub-topic-snapshot-create`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | ID of the project from which the subscription is receiving messages. | Optional | 
| subscription_id | The subscription whose backlog the snapshot retains. | Required | 
| labels | Input format: &quot;key=val&quot; pairs sepearated by &quot;,&quot;. | Optional | 
| snapshot_id | The id of the snapshot. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudPubSubSnapshots.name | String | The name of the snapshot. | 
| GoogleCloudPubSubSnapshots.topic | Unknown | The name of the topic from which this snapshot is retaining messages. | 
| GoogleCloudPubSubSnapshots.expireTime | Date | The snapshot is guaranteed to exist up until this time. | 
| GoogleCloudPubSubSnapshots.labels | Unknown | An object containing a list of &quot;key&quot;: value pairs | 


##### Command Example
```!gcp-pubsub-topic-snapshot-create project_id=dmst-integrations subscription_id=test_sub_2 snapshot_id=doc_snapshot```

##### Context Example
```
{
    "GoogleCloudPubSubSnapshots": {
        "expireTime": "2020-04-23T13:37:26.199Z",
        "name": "projects/dmst-integrations/snapshots/doc_snapshot",
        "topic": "projects/dmst-integrations/topics/dmst-topic"
    }
}
```

##### Human Readable Output
### Snapshot **doc_snapshot** was created successfully
|Expire Time|Name|Topic|
|---|---|---|
| 2020-04-23T13:37:26.199Z | projects/dmst-integrations/snapshots/doc_snapshot | projects/dmst-integrations/topics/dmst-topic |


### gcp-pubsub-topic-snapshot-update
***
Updates an existing snapshot. Snapshots are used in gcp-pubsub-topic-messages-seek command.


##### Base Command

`gcp-pubsub-topic-snapshot-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The ID of the project from which the subscription is receiving messages. | Optional | 
| expire_time | The snapshot is guaranteed to exist up until this time. A newly-created snapshot expires no later than 7 days from the time of its creation.<br/><br/>A timestamp in RFC3339 UTC &quot;Zulu&quot; format, accurate to nanoseconds. Example: &quot;2020-04-01T08:01:23.045678910Z&quot; | Optional | 
| labels | Input format: &quot;key=val&quot; pairs sepearated by &quot;,&quot;. | Optional | 
| snapshot_id | The id of the snapshot. | Required | 
| update_mask | Indicates which fields in the provided snapshot to update.<br/>A comma-separated list of fields. Example: &quot;labels,topic,expireTime&quot;. | Required | 
| topic_id | The ID of the topic from which this snapshot is retaining messages. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudPubSubSnapshots.name | String | The name of the snapshot. | 
| GoogleCloudPubSubSnapshots.topic | Unknown | The name of the topic from which this snapshot is retaining messages. | 
| GoogleCloudPubSubSnapshots.expireTime | Date | The snapshot is guaranteed to exist up until this time. | 
| GoogleCloudPubSubSnapshots.labels | Unknown | An object containing a list of &quot;key&quot;: value pairs | 


##### Command Example
```!gcp-pubsub-topic-snapshot-update project_id=dmst-integrations subscription_id=test_sub_2 snapshot_id=doc_snapshot labels="doc=true" update_mask=labels topic_id=dmst-topic```

##### Context Example
```
{
    "GoogleCloudPubSubSnapshots": {
        "expireTime": "2020-04-23T13:37:26.199Z",
        "labels": {
            "doc": "true"
        },
        "name": "projects/dmst-integrations/snapshots/doc_snapshot",
        "topic": "projects/dmst-integrations/topics/dmst-topic"
    }
}
```

##### Human Readable Output
### Snapshot **doc_snapshot** was updated successfully
|Expire Time|Labels|Name|Topic|
|---|---|---|---|
| 2020-04-23T13:37:26.199Z | doc: true | projects/dmst-integrations/snapshots/doc_snapshot | projects/dmst-integrations/topics/dmst-topic |


### gcp-pubsub-topic-snapshot-delete
***
Removes an existing snapshot.


##### Base Command

`gcp-pubsub-topic-snapshot-delete`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The ID of the project from which the subscription is receiving messages. | Optional | 
| snapshot_id | The id of the snapshot. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!gcp-pubsub-topic-snapshot-delete project_id=dmst-integrations snapshot_id=doc_snapshot```

##### Context Example
```
{}
```

##### Human Readable Output
Snapshot **doc_snapshot** was deleted successfully


### gcp-pubsub-topic-snapshot-delete
***
Removes an existing snapshot.


##### Base Command

`gcp-pubsub-topic-ack-messages`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription that will have the messages acked. | Required | 
| ack_ids | List of comma separated ids to ACK, as received from "gcp-pubsub-topic-messages-pull" or from "fetch-incidents". | Required | 
| project_id | The project id that the messages were pulled from. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!gcp-pubsub-topic-ack-messages ack_ids=example_ack_id subscription_id=test_sub_2```

##### Context Example
```
{}
```

##### Human Readable Output
### Subscription test_sub_2 had the following ids acknowledged
|ACK ID|
|---|
| example_ack_id |