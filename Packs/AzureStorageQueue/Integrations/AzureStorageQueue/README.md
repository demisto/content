# Azure Storage Queue
Create and Manage Azure Storage Queues and Messages.
This integration was integrated and tested with version "2020-10-02" of Azure Storage Queue

## Configure Azure Storage Queue in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Storage account name |  | True |
| Account SAS Token |  | False |
| Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
| Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Maximum incidents for one fetch. | Default is 10. Maximum is 32 \(due to an API limit\). | False |
| Queue name | The name of the queue from which the messages will be retrieved. | False |
| Incident type |  | False |
| Fetch incidents |  | False |


## Shared Access Signatures (SAS) Permissions
In order to use the integration use-cases, 
please make sure your SAS token contains the following permissions:
  1. 'Queue' service.
  2. 'Service' and 'Object' resource types.
  3. 'Read', 'Write', 'Delete', 'List', 'Create', 'Add', 'Update', 'Process' and 'Immutable storage' permissions.
  
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| queue_name | The name of the Queue to create.  Rules for naming queues can be found here: https://docs.microsoft.com/en-us/rest/api/storageservices/naming-queues-and-metadata. | Required | 


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
| expiration | Specifies the time-to-live (expiration) interval for the message, in seconds.<br/>the maximum time-to-live can be any positive number, as well as -1 indicating that the message does not expire.<br/>Default expiration time is 7 days. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageQueue.Queue.Message.MessageId | String | Message ID. | 
| AzureStorageQueue.Queue.Message.InsertionTime | Date | Message insertion time. | 
| AzureStorageQueue.Queue.Message.ExpirationTime | Date | Message expiration time. | 
| AzureStorageQueue.Queue.Message.PopReceipt | String | Message pop receipt value. This value changes each time the message is retrieved or updated and used to ensure that message has not been dequeued by another user before deleting or updating the message. | 
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
                "ExpirationTime": "2021-12-05T11:55:31",
                "InsertionTime": "2021-11-28T11:55:31",
                "MessageId": "0d579602-222f-4256-9003-8772f0d65399",
                "PopReceipt": "AgAAAAMAAAAAAAAAN734107k1wE=",
                "TimeNextVisible": "2021-11-28T11:55:31"
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
>| 0d579602-222f-4256-9003-8772f0d65399 | 2021-12-05T11:55:31 | 2021-11-28T11:55:31 | 2021-11-28T11:55:31 | AgAAAAMAAAAAAAAAN734107k1wE= |


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
| AzureStorageQueue.Queue.Message.PopReceipt | String | Message pop receipt value. This value changes each time the message is retrieved or updated and used to ensure that message has not been dequeued by another user before deleting or updating the message. | 
| AzureStorageQueue.Queue.Message.TimeNextVisible | Date | Message next visible time. | 
| AzureStorageQueue.Queue.Message.MessageText | String | Message text content. | 
| AzureStorageQueue.Queue.name | String | Queue name. | 
| AzureStorageQueue.Queue.Message.DequeueCount | Number | Indicates how many times a message has been retrieved. | 


#### Command Example
```!azure-storage-queue-message-get limit="1" queue_name="xsoar-test"```

#### Context Example
```json
{
    "AzureStorageQueue": {
        "Queue": {
            "Message": [
                {
                    "DequeueCount": "1",
                    "ExpirationTime": "2021-12-05T11:55:31",
                    "InsertionTime": "2021-11-28T11:55:31",
                    "MessageId": "0d579602-222f-4256-9003-8772f0d65399",
                    "MessageText": "test demo",
                    "PopReceipt": "AgAAAAMAAAAAAAAAziUx7U7k1wE=",
                    "TimeNextVisible": "2021-11-28T11:56:06"
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
>| test demo | 0d579602-222f-4256-9003-8772f0d65399 | AgAAAAMAAAAAAAAAziUx7U7k1wE= | 1 | 2021-12-05T11:55:31 | 2021-11-28T11:55:31 | 2021-11-28T11:56:06 |


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
```!azure-storage-queue-message-peek limit="1" queue_name="xsoar-test"```

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
| pop_receipt | Message PopReceipt parameter. This value changes each time the message is retrieved or updated and used to ensure that message has not been dequeued by another user before deleting or updating the message. | Required | 
| base64_encoding | Indicates whether the message content should be encoded or not. Default is 'False'. Possible values are: False, True. Default is False. | Optional | 
| visibility_time_out | Specifies the new visibility timeout value of the message. The new value must be larger than or equal to 0, and cannot be larger than 7 days. The visibility timeout of a message cannot be set to a value later than the expiry time. Default is 0. Possible values are: . Default is 0. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-message-update queue_name="test-xsoar" message_content="new content" message_id="ea0db196-dad3-4c12-b845-dc6223739870" pop_receipt="AgAAAAMAAAAAAAAA0xNSmE7k1wE="```

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
| pop_receipt | Message PopReceipt parameter. This value changes each time the message is retrieved or updated and used to ensure that message has not been dequeued by another user before deleting or updating the message. | Required | 
| queue_name | The name of the Queue. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-queue-message-delete queue_name="test-xsoar" message_id="66df94e9-4a66-428a-9c4a-e2a3c4fe7284" pop_receipt="AgAAAAMAAAAAAAAA0xNSmE7k1wE="```

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