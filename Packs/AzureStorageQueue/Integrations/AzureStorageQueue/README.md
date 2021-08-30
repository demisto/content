# Azure Storage Queue
Create and Manage Azure Storage Queues and Messages.
This integration was integrated and tested with version "2020-10-02" of Azure Storage Queue

## Configure Azure Storage Queue on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Storage Queue.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Storage account name |  | True |
    | Account SAS Token |  | True |
    | Use system proxy |  | False |
    | Trust any certificate |  | False |
    | Fetch incidents |  | False |
    | Maximum incidents for one fetch. | Default is 10. Maximum is 32. | False |
    | Queue name |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-storage-queue-queue-list
***
List queues in storage account.


#### Base Command

`azure-storage-queue-queue-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of queues to retrieve. Default is 50. Default is 50. | Optional | 
| prefix | Filters the results to return only queues with names that begin with the specified prefix. | Optional | 
| page | Page number. Default is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageQueue.Name | String | Queue name | 


#### Command Example
```!azure-storage-queue-queue-list limit="2" prefix="xs"```

#### Context Example
```json
{
    "AzureStorageQueue": {
        "Queue": [
            {
                "Name": "xsoar-test"
            },
            {
                "Name": "xsoar-test-demo-test"
            }
        ]
    }
}
```

#### Human Readable Output

>### Queues List:
> Current page size: 2
> Showing page 1 out others that may exist
>|Name|
>|---|
>| xsoar-test |
>| xsoar-test-demo-test |


### azure-storage-queue-queue-create
***
Create new queue.


#### Base Command

`azure-storage-queue-queue-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_name | Queue name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-queue-create queue_name="xsoar-new-test"```

#### Human Readable Output

>Queue xsoar-new-test successfully created.

### azure-storage-queue-queue-delete
***
Delete queue.


#### Base Command

`azure-storage-queue-queue-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_name | Queue name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-queue-delete queue_name="xsoar-new-test"```

#### Human Readable Output

>Queue xsoar-new-test successfully deleted.

### azure-storage-queue-message-create
***
Add a new message to the back of the message queue.


#### Base Command

`azure-storage-queue-message-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_content | Message content. | Required | 
| queue_name | Queue name. | Required | 
| base64_encoding | Indicates whether the message should be encoded or not. Possible values are: False, True. | Optional | 
| visibility_time_out | Specifies the new visibility timeout value, in seconds, relative to server time. Must be larger than or equal to 0, and cannot be larger than 7 days. The visibility timeout of a message cannot be set to a value later than the expiry time.<br/>Default is 0. | Optional | 
| time_to_live | Specifies the time-to-live interval for the message, in seconds.<br/>the maximum time-to-live can be any positive number, as well as -1 indicating that the message does not expire.<br/>Default time-to-live is 7 days. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageQueue.Message.MessageId | String | Message ID | 
| AzureStorageQueue.Message.InsertionTime | Date | Message insertion time | 
| AzureStorageQueue.Message.ExpirationTime | Date | Message expiration time | 
| AzureStorageQueue.Message.PopReceipt | String | Message pop receipt | 
| AzureStorageQueue.Message.TimeNextVisible | Date | Message next visible time | 
| AzureStorageQueue.Message.queue_name | String | Queue name. | 


#### Command Example
```!azure-storage-queue-message-create message_content="test demo" queue_name="xsoar-test" base64_encoding="True"```

#### Context Example
```json
{
    "AzureStorageQueue": {
        "Message": {
            "ExpirationTime": "2021-09-02T15:19:45",
            "InsertionTime": "2021-08-26T15:19:45",
            "MessageId": "8392e195-cec1-4f73-87a2-d9f3206be9f2",
            "PopReceipt": "AgAAAAMAAAAAAAAAi/sezY2a1wE=",
            "TimeNextVisible": "2021-08-26T15:19:45",
            "queue_name": "xsoar-test"
        }
    }
}
```

#### Human Readable Output

>### xsoar-test Queue message:
>|Message Id|Expiration Time|Insertion Time|Time Next Visible|Pop Receipt|
>|---|---|---|---|---|
>| 8392e195-cec1-4f73-87a2-d9f3206be9f2 | 2021-09-02T15:19:45 | 2021-08-26T15:19:45 | 2021-08-26T15:19:45 | AgAAAAMAAAAAAAAAi/sezY2a1wE= |


### azure-storage-queue-message-get
***
Retrieves messages from the front of the queue.Retrieved messages will move to the end of the queue,and will be visible after 'TimeNextVisible' param.


#### Base Command

`azure-storage-queue-message-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of messages to retrieve. Default is 1, maximum is 32. Default is 1. | Optional | 
| queue_name | Queue name. | Required | 
| visibility_time_out | Specifies the new visibility timeout value, in seconds, relative to server time. The default value is 30 seconds.<br/>A specified value must be larger than or equal to 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageQueue.Message.MessageId | String | Message ID | 
| AzureStorageQueue.Message.InsertionTime | Date | Message insertion time | 
| AzureStorageQueue.Message.ExpirationTime | Date | Message expiration time | 
| AzureStorageQueue.Message.PopReceipt | String | Message pop receipt | 
| AzureStorageQueue.Message.TimeNextVisible | Date | Message next visible time | 
| AzureStorageQueue.Message.MessageText | String | Message text content | 
| AzureStorageQueue.Message.queue_name | String | Queue name. | 


#### Command Example
```!azure-storage-queue-message-get limit="2" queue_name="xsoar-test"```

#### Context Example
```json
{
    "AzureStorageQueue": {
        "Message": {
            "DequeueCount": "1",
            "ExpirationTime": "2021-09-02T15:19:45",
            "InsertionTime": "2021-08-26T15:19:45",
            "MessageId": "8392e195-cec1-4f73-87a2-d9f3206be9f2",
            "MessageText": "test demo",
            "PopReceipt": "AgAAAAMAAAAAAAAAlFM45Y2a1wE=",
            "TimeNextVisible": "2021-08-26T15:20:25",
            "queue_name": "xsoar-test"
        }
    }
}
```

#### Human Readable Output

>### xsoar-test Queue messages:
>|Message Text|Message Id|Pop Receipt|Dequeue Count|Expiration Time|Insertion Time|Time Next Visible|
>|---|---|---|---|---|---|---|
>| test demo | 8392e195-cec1-4f73-87a2-d9f3206be9f2 | AgAAAAMAAAAAAAAAlFM45Y2a1wE= | 1 | 2021-09-02T15:19:45 | 2021-08-26T15:19:45 | 2021-08-26T15:20:25 |


### azure-storage-queue-message-peek
***
Retrieves messages from the front of the queue.


#### Base Command

`azure-storage-queue-message-peek`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of messages to retrieve. Default is 1, maximum is 32. Default is 1. | Optional | 
| queue_name | Queue name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageQueue.Message.MessageId | String | Message ID | 
| AzureStorageQueue.Message.InsertionTime | Date | Message insertion time | 
| AzureStorageQueue.Message.ExpirationTime | Date | Message expiration time | 
| AzureStorageQueue.Message.TimeNextVisible | Date | Message next visible time | 
| AzureStorageQueue.Message.MessageText | String | Message text content | 
| AzureStorageQueue.Message.queue_name | String | Queue name. | 


#### Command Example
```!azure-storage-queue-message-peek limit="2" queue_name="xsoar-test"```

#### Human Readable Output

>### xsoar-test Queue messages:
>**No entries.**


### azure-storage-queue-message-dequeue
***
Dequeue a message from the front of the queue.


#### Base Command

`azure-storage-queue-message-dequeue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_name | Queue name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-message-dequeue queue_name="xsoar-test"```

#### Human Readable Output

>There are no messages in xsoar-test queue.

### azure-storage-queue-message-update
***
Update message in the  queue.


#### Base Command

`azure-storage-queue-message-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_name | Queue name. | Required | 
| message_content | Message content. | Required | 
| message_id | Queue message ID. | Required | 
| pop_receipt | Queue message PopReceipt parameter. | Required | 
| base64_encoding | Indicates whether the message should be encoded or not. Possible values are: False, True. Default is False. | Optional | 
| visibility_time_out | Specifies the new visibility timeout value. Possible values are: . Default is 30. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-message-update queue_name="xsoar-test" message_content="new content" message_id="c75bf5ab-ae44-4d64-b5ef-0cb7a7533885" pop_receipt="AgAAAAMAAAAAAAAAGpu5VlGX1wE="```

#### Human Readable Output

>The message in xsoar-test successfully updated.

### azure-storage-queue-message-delete
***
Delete Queue message.


#### Base Command

`azure-storage-queue-message-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | Message ID. | Required | 
| pop_receipt | Message PopReceipt param. | Required | 
| queue_name | Queue name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-message-delete queue_name="xsoar-test" message_id="6ae39eb4-eabf-468c-a380-50af7281965c" pop_receipt="AgAAAAMAAAAAAAAAGpu5VlGX1wE="```

#### Human Readable Output

>Message in xsoar-test successfully deleted.

### azure-storage-queue-message-clear
***
Delete all messages from the specified queue.


#### Base Command

`azure-storage-queue-message-clear`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_name | Qeueu name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-message-clear queue_name="xsoar-test"```

#### Human Readable Output

>xsoar-test was cleared of messages successfully.
