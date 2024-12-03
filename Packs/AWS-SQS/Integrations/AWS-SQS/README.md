Amazon Web Services Simple Queuing Service (SQS)

For more information regarding the AWS SQS service, please visit the official documentation found [here](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs.html).

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

## Configure AWS - SQS in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| AWS Default Region | The AWS Region for this instance of the integration. For example, us-west-2 | False        |
| Role Arn | The Amazon Resource Name (ARN) role used for EC2 instance authentication. If this is used, an access key and secret key are not required. | False        |
| Role Session Name | A descriptive name for the assumed role session. For example, xsiam-IAM.integration-Role_SESSION | False        |
| Access Key  | The access key ID used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required. | False        |
| Secret Key | The secret key used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required. | False        |
| Role Session Duration | The maximum length of each session in seconds. Default: 900 seconds. The XSOAR integration will have the permissions assigned only when the session is initiated and for the defined duration. | False        |
| Queue URL | URL of an existing Amazon SQS queue. | False        |
| Timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout (for example 60) or also the connect timeout followed after a comma (for example 60,10). If a connect timeout is not specified a default of 10 second will be used. | False        |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. More details about the retries strategy is available [here](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/retries.html). | False        |
| Fetch incidents |  | False        |
| Maximum incidents for one fetch. Hard cap of 100. | Maximum number of incidents for a single fetch. | 10           |
| First fetch timestamp | First fetch query `<number> <time unit>`, e.g., `7 days`. Default `3 days`)  | False        |
| Incident type |  | False        |
| Use system proxy settings |  | False        |
| Trust any certificate (not secure) |  | False        |
| Parse SQS message body as a JSON string |  | False |


### There are three options to sign in to the service:
1. Provide Access Key ID and Secret Key ID.
2. Provide Role ARN and Access Key ID and Secret Key ID.
3. Do not provide any credentials or Role ARN other than permissions pulled from the service metadata.


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-sqs-get-queue-url
***
Returns the URL of an existing queue. To access a queue that belongs to another AWS account, use the queueOwnerAWSAccountId parameter to specify the account ID of the queues owner. The queues owner must grant you permission to access the queue.


#### Base Command

`aws-sqs-get-queue-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queueName | The name of the queue. | Required | 
| queueOwnerAWSAccountId | The AWS account ID of the account that created the queue. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SQS.Queues.QueueUrl | string | The URL of the queue. | 


#### Command Example
```!aws-sqs-get-queue-url queueName=test ```

#### Human Readable Output

**AWS SQS Queues**

| QueueUrl | test.queue.amazonaws.com/1234567/test |
| --- | --- |

### aws-sqs-list-queues
***
Returns a list of your queues. The maximum number of queues that can be returned is 1,000. If you specify a value for the optional QueueNamePrefix parameter, only queues with a name that begins with the specified value are returned.


#### Base Command

`aws-sqs-list-queues`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queueNamePrefix | A string to use for filtering the list results. Only those queues whose name begins with the specified string are returned.  Queue names are case-sensitive. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SQS.Queues.QueueUrl | string | The URL of the queue. | 


#### Command Example
```!aws-sqs-list-queues ```

#### Human Readable Output

**AWS SQS Queues**

| **QueueUrl**  |
| --- |
| test.queue.amazonaws.com/1234567/test1 |
| test.queue.amazonaws.com/1234567/test2 |


### aws-sqs-send-message
***
Delivers a message to the specified queue.


#### Base Command

`aws-sqs-send-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queueUrl | The URL of the Amazon SQS queue to which a message is sent. | Required | 
| messageBody | The message to send. The maximum string size is 256 KB. | Required | 
| delaySeconds | The length of time, in seconds, for which to delay a specific message. Valid values 0 to 900. Maximum 15 minutes. | Optional | 
| messageGroupId | This parameter applies only to FIFO queues. The tag that specifies that a message belongs to a specific message group. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SQS.Queues.SentMessages.MD5OfMessageBody | string | An MD5 digest of the non-URL-encoded message attribute string. | 
| AWS.SQS.Queues.SentMessages.MD5OfMessageAttributes | string | An MD5 digest of the non-URL-encoded message attribute string. | 
| AWS.SQS.Queues.SentMessages.MessageId | string | An attribute containing the MessageId of the message sent to the queue. | 
| AWS.SQS.Queues.SentMessages.SequenceNumber | string | This parameter applies only to FIFO \(first-in-first-out\) queues. The large, non-consecutive number that Amazon SQS assigns to each message. | 


#### Command Example
``` !aws-sqs-send-message queueUrl=test.queue.amazonaws.com/1234567/test2 messageBody="test"```

#### Human Readable Output

**AWS SQS Queues sent messages**

| MD5OfMessageBody | 123a4bcd4621d373cade4e832627b4f6 |
| --- | --- |
| MessageId | 1a2bc456-1e23-45e6-b789-b1af23c4f56f |
| QueueUrl | test.queue.amazonaws.com/1234567/test2 |



### aws-sqs-create-queue
***
Creates a new standard or FIFO queue. You can pass one or more attributes in the request.


#### Base Command

`aws-sqs-create-queue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queueName | The name of the new queue. | Required | 
| delaySeconds | The length of time, in seconds, for which the delivery of all messages in the queue is delayed. Valid values An integer from 0 to 900 seconds (15 minutes). The default is 0 (zero). | Optional | 
| maximumMessageSize | The limit of how many bytes a message can contain before Amazon SQS rejects it. Valid values An integer from 1,024 bytes (1 KiB) to 262,144 bytes (256 KiB). The default is 262,144 (256 KiB). | Optional | 
| messageRetentionPeriod | The length of time, in seconds, for which Amazon SQS retains a message. Valid values An integer from 60 seconds (1 minute) to 1,209,600 seconds (14 days). The default is 345,600 (4 days). | Optional | 
| receiveMessageWaitTimeSeconds | The length of time, in seconds, for which a ReceiveMessage  action waits for a message to arrive. Valid values An integer from 0 to 20 (seconds). The default is 0 (zero). | Optional | 
| visibilityTimeout | The visibility timeout for the queue. Valid values An integer from 0 to 43,200 (12 hours). The default is 30. | Optional | 
| kmsDataKeyReusePeriodSeconds | The length of time, in seconds, for which Amazon SQS can reuse a data key to encrypt or decrypt messages before calling AWS KMS again. An integer representing seconds, between 60 seconds (1 minute) and 86,400 seconds (24 hours). The default is 300 (5 minutes). A shorter time period provides better security but results in more calls to KMS which might incur charges after Free Tier. | Optional | 
| kmsMasterKeyId | The ID of an AWS-managed customer master key (CMK) for Amazon SQS or a custom CMK. | Optional | 
| policy | The queues policy. A valid AWS policy. | Optional | 
| fifoQueue | Designates a queue as FIFO. Possible values are: True, False. | Optional | 
| contentBasedDeduplication | Enables content-based deduplication. Possible values are: True, False. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SQS.Queues.QueueUrl | unknown | The URL of the created Amazon SQS queue. | 


#### Command Example
``` !aws-sqs-create-queue queueName=test3```

#### Human Readable Output

**AWS SQS Queues**

| QueueUrl | test.queue.amazonaws.com/1234567/test3 |
| --- | --- |

### aws-sqs-delete-queue
***
Deletes the queue specified by the QueueUrl , regardless of the queue's contents. If the specified queue doesn't exist, Amazon SQS returns a successful response.


#### Base Command

`aws-sqs-delete-queue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queueUrl | The URL of the Amazon SQS queue to delete. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-sqs-delete-queue queueUrl=example.com/123456789/test3```

#### Human Readable Output

The Queue has been deleted


### aws-sqs-purge-queue
***
Deletes the messages in a queue specified by the QueueURL parameter.


#### Base Command

`aws-sqs-purge-queue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queueUrl | The URL of the queue from which the PurgeQueue action deletes messages. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-sqs-purge-queue queueUrl=example.com/123456789/test2```

#### Human Readable Output

The Queue has been Purged
