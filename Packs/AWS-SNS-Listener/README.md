Amazon Simple Notification Service (SNS) is a managed service that provides message delivery from publishers to subscribers. Publishers communicate asynchronously with subscribers by sending messages to a topic, which is a logical access point and communication channel. Clients can subscribe to the SNS topic and receive published messages using a supported endpoint type, such as Amazon Kinesis Data Firehose, Amazon SQS, AWS Lambda, HTTP, email, mobile push notifications, and mobile text messages (SMS).

## What does this pack do
The AWS SNS Listener supports two types of POST requests:
* SubscriptionConfirmation: Extract the subscription URL send subscription confirmation.
* Notification: Extract the subject and message body and creates a Cortex XSOAR / Cortex XSIAM incident.