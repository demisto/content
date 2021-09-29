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
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Fetch incidents |  | False |
    | Maximum incidents for one fetch. | Default is 10. Maximum is 32. | False |
    | The name of the Queue to fetch incidents. |  | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-storage-queue-list
***
List queues in storage account.


#### Base Command

`azure-storage-queue-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of queues to retrieve. Default is 50. Default is 50. | Optional | 
| prefix | Filters the results to return only queues with names that begin with the specified prefix. | Optional | 
| page | Page number. Default is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageQueue.Queue.name | String | Queue name. | 


#### Command Example
```!azure-storage-queue-list limit="2" prefix="xs"```

#### Context Example
```json
{
    "AzureStorageQueue": {
        "Queue": [
            {
                "name": "xsoar-new-test"
            },
            {
                "name": "xsoar-test"
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
>| xsoar-new-test |
>| xsoar-test |


### azure-storage-queue-create
***
Create new queue in storage account.


#### Base Command

`azure-storage-queue-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_name | The name of the Queue to create. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-create queue_name="xsoar-test"```

#### Human Readable Output

>Queue xsoar-test successfully created.

### azure-storage-queue-delete
***
Delete queue from storage account.


#### Base Command

`azure-storage-queue-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_name | The name of the Queue to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-delete queue_name="xsoar-test"```

#### Human Readable Output

>Queue xsoar-test successfully deleted.

### azure-storage-queue-message-create
***
Add a new message to the back of the queue.


#### Base Command

`azure-storage-queue-message-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_content | The text content of the new message. | Required | 
| queue_name | The name of the Queue. | Required | 
| base64_encoding | Indicates whether the message should be encoded or not. Default is 'False'. Possible values are: False, True. Default is False. | Optional | 
| visibility_time_out | Specifies the new visibility timeout value, in seconds, relative to server time. Must be larger than or equal to 0, and cannot be larger than 7 days. The visibility timeout of a message cannot be set to a value later than the expiry time.<br/>Default is 0. | Optional | 
| time_to_live | Specifies the time-to-live interval for the message, in seconds.<br/>the maximum time-to-live can be any positive number, as well as -1 indicating that the message does not expire.<br/>Default time-to-live is 7 days. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageQueue.Queue.Message.MessageId | String | Message ID. | 
| AzureStorageQueue.Queue.Message.InsertionTime | Date | Message insertion time. | 
| AzureStorageQueue.Queue.Message.ExpirationTime | Date | Message expiration time. | 
| AzureStorageQueue.Queue.Message.PopReceipt | String | Message pop receipt value. | 
| AzureStorageQueue.Queue.Message.TimeNextVisible | Date | Message next visible time. | 
| AzureStorageQueue.Queue.name | String | Queue name. | 


#### Command Example
```!azure-storage-queue-message-create message_content="test demo" queue_name="xsoar-test" base64_encoding="True"```

#### Context Example
```json
{
    "AzureStorageQueue": {
        "Queue": {
            "Message": {
                "ExpirationTime": "2021-09-30T09:14:01",
                "InsertionTime": "2021-09-23T09:14:01",
                "MessageId": "f802b202-a939-44e6-84a9-84f4405be6d8",
                "PopReceipt": "AgAAAAMAAAAAAAAAzCEfWVuw1wE=",
                "TimeNextVisible": "2021-09-23T09:14:01"
            },
            "name": "xsoar-test"
        }
    }
}
```

#### Human Readable Output

>### xsoar-test Queue message:
>|Message Id|Expiration Time|Insertion Time|Time Next Visible|Pop Receipt|
>|---|---|---|---|---|
>| f802b202-a939-44e6-84a9-84f4405be6d8 | 2021-09-30T09:14:01 | 2021-09-23T09:14:01 | 2021-09-23T09:14:01 | AgAAAAMAAAAAAAAAzCEfWVuw1wE= |


### azure-storage-queue-message-get
***
Retrieves messages from the front of the queue. Retrieved messages will move to the end of the queue,and will be visible after 'TimeNextVisible' param.


#### Base Command

`azure-storage-queue-message-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of messages to retrieve. Default is 1, maximum is 32. Default is 1. | Optional | 
| queue_name | The name of the Queue. | Required | 
| visibility_time_out | Specifies the new visibility timeout value, in seconds, relative to server time. The default value is 30 seconds.<br/>A specified value must be larger than or equal to 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageQueue.Queue.Message.MessageId | String | Message ID. | 
| AzureStorageQueue.Queue.Message.InsertionTime | Date | Message insertion time. | 
| AzureStorageQueue.Queue.Message.ExpirationTime | Date | Message expiration time. | 
| AzureStorageQueue.Queue.Message.PopReceipt | String | Message pop receipt value. | 
| AzureStorageQueue.Queue.Message.TimeNextVisible | Date | Message next visible time. | 
| AzureStorageQueue.Queue.Message.MessageText | String | Message text content. | 
| AzureStorageQueue.Queue.name | String | Queue name. | 
| AzureStorageQueue.Queue.Message.DequeueCount | Number | Indicates how many times a message has been retrieved. | 


#### Command Example
```!azure-storage-queue-message-get limit="2" queue_name="xsoar-test"```

#### Context Example
```json
{
    "AzureStorageQueue": {
        "Queue": {
            "Message": [
                {
                    "DequeueCount": "1",
                    "ExpirationTime": "2021-09-30T09:14:01",
                    "InsertionTime": "2021-09-23T09:14:01",
                    "MessageId": "f802b202-a939-44e6-84a9-84f4405be6d8",
                    "MessageText": "test demo",
                    "PopReceipt": "AgAAAAMAAAAAAAAA82JFcVuw1wE=",
                    "TimeNextVisible": "2021-09-23T09:14:41"
                }
            ],
            "name": "xsoar-test"
        }
    }
}
```

#### Human Readable Output

>### xsoar-test Queue messages:
>|Message Text|Message Id|Pop Receipt|Dequeue Count|Expiration Time|Insertion Time|Time Next Visible|
>|---|---|---|---|---|---|---|
>| test demo | f802b202-a939-44e6-84a9-84f4405be6d8 | AgAAAAMAAAAAAAAA82JFcVuw1wE= | 1 | 2021-09-30T09:14:01 | 2021-09-23T09:14:01 | 2021-09-23T09:14:41 |


### azure-storage-queue-message-peek
***
Retrieves messages from the front of the queue. The command does not alter the visibility of the message.


#### Base Command

`azure-storage-queue-message-peek`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of messages to retrieve. Default is 1, maximum is 32. Default is 1. | Optional | 
| queue_name | The name of the Queue. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageQueue.Queue.Message.MessageId | String | Message ID. | 
| AzureStorageQueue.Queue.Message.InsertionTime | Date | Message insertion time. | 
| AzureStorageQueue.Queue.Message.ExpirationTime | Date | Message expiration time. | 
| AzureStorageQueue.Queue.Message.MessageText | String | Message text content. | 
| AzureStorageQueue.Queue.name | String | Queue name. | 
| AzureStorageQueue.Queue.Message.DequeueCount | Number | Indicates how many times a message has been retrieved. | 


#### Command Example
```!azure-storage-queue-message-peek limit="2" queue_name="xsoar-test"```

#### Context Example
```json
{
    "AzureStorageQueue": {
        "Queue": {
            "Message": [],
            "name": "xsoar-test"
        }
    }
}
```

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
| queue_name | The name of the Queue. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-message-dequeue queue_name="xsoar-test"```

#### Human Readable Output

>There are no messages in xsoar-test queue.

### azure-storage-queue-message-update
***
Update message content in the  queue.


#### Base Command

`azure-storage-queue-message-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_name | The name of the Queue. | Required | 
| message_content | New message content. | Required | 
| message_id | The ID of the message to update. | Required | 
| pop_receipt | Message PopReceipt parameter. | Required | 
| base64_encoding | Indicates whether the message content should be encoded or not. Default is 'False'. Possible values are: False, True. Default is False. | Optional | 
| visibility_time_out | Specifies the new visibility timeout value of the message. The new value must be larger than or equal to 0, and cannot be larger than 7 days. The visibility timeout of a message cannot be set to a value later than the expiry time. Default is 0. Possible values are: . Default is 0. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-message-update queue_name="test-xsoar" message_content="new content" message_id="9b67986e-3b02-464c-a81b-dc332f473e4b" pop_receipt="AgAAAAMAAAAAAAAAD+s2EFuw1wE="```

#### Human Readable Output

>The message in test-xsoar successfully updated.

### azure-storage-queue-message-delete
***
Delete message from a Queue.


#### Base Command

`azure-storage-queue-message-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The ID of the message to delete. | Required | 
| pop_receipt | Message PopReceipt parameter. | Required | 
| queue_name | The name of the Queue. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-message-delete queue_name="test-xsoar" message_id="37d87b60-abef-4769-b2a0-ff0abb5830a2" pop_receipt="AgAAAAMAAAAAAAAAD+s2EFuw1wE="```

#### Human Readable Output

>Message in test-xsoar successfully deleted.

### azure-storage-queue-message-clear
***
Delete all messages from the specified Queue.


#### Base Command

`azure-storage-queue-message-clear`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_name | The name of the queue. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-message-clear queue_name="xsoar-test"```

#### Human Readable Output

>xsoar-test was cleared of messages successfully.
