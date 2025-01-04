Amazon Web Services Simple Notification Service (SNS)

For more information regarding the AWS SNS service, please visit the official documentation found [here](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html).

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

## Configure AWS - SNS in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| AWS Default Region |  | True |
| Role Arn | When using Access Key and Secret Key, there is no need to use Role Arn | False |
| Role Session Name |  | False |
| Access Key |  | True |
| Secret Key |  | True |
| Role Session Duration |  | False |
| Timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| AWS STS Regional Endpoints | Sets the AWS_STS_REGIONAL_ENDPOINTS environment variable to specify the AWS STS endpoint resolution logic. By default, this option is set to “legacy” in AWS. Leave empty if the environment variable is already set using server configuration. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-sns-create-subscription
***
Subscribes an endpoint to an Amazon SNS topic. If the endpoint type is HTTP/S or email, or if the endpoint and the topic are not in the same Amazon Web Services account, the endpoint owner must run the ConfirmSubscription action to confirm the subscription.


#### Base Command

`aws-sns-create-subscription`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topicArn | The ARN of the topic you want to subscribe to. | Required | 
| protocol | The protocol that you want to use. Possible values are: http, https, email, email-json, sms, sqs, application, lambda, firehose. | Required | 
| endpoint | The endpoint that you want to receive notifications. | Optional | 
| returnSubscriptionArn | Sets whether the response from the Subscribe request includes the subscription ARN, even if the subscription is not yet confirmed. Possible values are: True, False. | Optional | 
| deliveryPolicy | The policy that defines how Amazon SNS retries failed deliveries to HTTP/S endpoints. | Optional | 
| filterPolicy | The simple JSON object that lets your subscriber receive only a subset of messages, rather than receiving every message published to the topic. | Optional | 
| rawMessageDelivery | When set to true , enables raw message delivery to Amazon SQS or HTTP/S endpoints. Possible values are: True, False. | Optional | 
| redrivePolicy | When specified, sends undeliverable messages to the specified Amazon SQS dead-letter queue. | Optional | 
| subscriptionRoleArn | The ARN of the IAM role that has the following: 1. Permission to write to the Kinesis Data Firehose delivery stream 2. Amazon SNS listed as a trusted entity. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SNS.Subscriptions.SubscriptionArn | string | The Subscription Arn | 


#### Command Example
``` ```

#### Human Readable Output



### aws-sns-list-topics
***
Returns a list of the requester's topics.


#### Base Command

`aws-sns-list-topics`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nextToken | Token returned by the previous ListTopics request. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SNS.Topics.TopicArn | string | The Topic ARN | 


#### Command Example
``` ```

#### Human Readable Output



### aws-sns-send-message
***
Sends a message to an Amazon SNS topic, a text message (SMS message) directly to a phone number, or a message to a mobile platform endpoint (when you specify the TargetArn ).


#### Base Command

`aws-sns-send-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topicArn | The topic you want to publish to. If you don't specify a value for the TopicArn parameter, you must specify a value for the PhoneNumber or TargetArn parameters. | Optional | 
| targetArn | If you don't specify a value for the TargetArn parameter, you must specify a value for the PhoneNumber or TopicArn parameters. | Optional | 
| phoneNumber | The phone number to which you want to deliver an SMS message. Use E.164 format. | Optional | 
| message | The message you want to send. | Required | 
| subject | Optional parameter to be used as the "Subject" line when the message is delivered to email endpoints. | Optional | 
| messageStructure | Set MessageStructure to json if you want to send a different message for each protocol. | Optional | 
| messageDeduplicationId | This parameter applies only to FIFO (first-in-first-out) topics. | Optional | 
| messageGroupId | This parameter applies only to FIFO (first-in-first-out) topics. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SNS.SentMessages | string | Unique identifier assigned to the published message. | 


#### Command Example
``` ```

#### Human Readable Output



### aws-sns-create-topic
***
Creates a new a topic to which notifications can be published. You can specify the attribute to create FIFO topic.


#### Base Command

`aws-sns-create-topic`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topicName | The name of the new topic. | Required | 
| deliveryPolicy | The policy that defines how Amazon SNS retries failed deliveries to HTTP/S endpoints. | Optional | 
| displayName | The display name to use for a topic with SMS subscriptions. | Optional | 
| fifoTopic | Set to true to create a FIFO topic. Possible values are: true, false. | Optional | 
| policy | The policy that defines who can access your topic. By default, only the topic owner can publish or subscribe to the topic. | Optional | 
| kmsMasterKeyId | The ID of an Amazon Web Services managed customer master key (CMK) for Amazon SNS or a custom CMK. | Optional | 
| contentBasedDeduplication | Enables content-based deduplication. Possible values are: True, False. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SNS.Topic.TopicArn | unknown | The ARN of the created Amazon SNS topic. | 


#### Command Example
``` ```

#### Human Readable Output



### aws-sns-delete-topic
***
Deletes a topic and all its subscriptions.


#### Base Command

`aws-sns-delete-topic`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topicArn | The ARN of the topic you want to delete. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-sns-list-subscriptions-by-topic
***
Returns a list of the subscriptions to a specific topic. Each call returns a limited list of subscriptions, up to 100.


#### Base Command

`aws-sns-list-subscriptions-by-topic`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topicArn | The ARN of the topic for which you wish to find subscriptions. | Required | 
| nextToken | Token returned by the previous ListTopics request. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SNS.Subscriptions.SubscriptionArn | unknown | The Subscription Arn | 


#### Command Example
``` ```

#### Human Readable Output
