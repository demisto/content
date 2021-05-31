<!-- HTML_DOC -->
<p>Use the AWS Simple Queue Service (SQS) integration to receive the messages from the queue. </p>
<p>This integration was integrated and tested with API Version 2012-11-05.</p>
<h2>Prerequisites</h2>
<p>It is important that you familiarize yourself with and complete all steps detailed in the <a href="https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication">AWS Integrations - Authentication</a>.</p>
<h2>Configure the AWS SQS Integration in Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for the SQS integration.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration.</li>
</ol><ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>AWS Default Region</strong></li>
<li><strong>Role Arn</strong></li>
<li><strong>Role Session Name</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Role Session Duration</strong></li>
<li>
<strong>QueueURL</strong>: the relevant URL is under the <strong>Details</strong> tab. </li>
</ul>

<h2>Fetched Incidents Data</h2>
<p>New messages from the queue are fetched.</p>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_62820238371528828296291">Get a queue URL: aws-sqs-get-queue-url</a></li>
<li><a href="#h_442820800231528828585443">List all queues: aws-sqs-list-queues</a></li>
<li><a href="#h_398305729441528828949972">Send a message: aws-sqs-send-message</a></li>
<li><a href="#h_801821297701528829379275">Create a queue: aws-sqs-create-queue</a></li>
<li><a href="#h_4728900091011528829585308">Delete a queue: aws-sqs-delete-queue</a></li>
<li><a href="#h_1452318441361528867523193">Delete messages from a queue: aws-sqs-purge-queue</a></li>
</ol>
<hr>
<h3 id="h_62820238371528828296291">Get a queue URL: aws-sqs-get-queue-url</h3>
<p>Return the URL of a queue.</p>
<h5>Command Example</h5>
<p><code>!aws-sqs-get-queue-url queueName=test</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>sqs:GetQueueUrl</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">queueName</td>
<td style="width: 535px;">The name of the queue</td>
</tr>
<tr>
<td style="width: 179px;">queueOwnerAWSAccountId</td>
<td style="width: 535px;">The AWS account ID of the account that created the queue</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">AWS.SQS.Queues.QueueUrl</td>
<td style="width: 503px;">The URL of the queue</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "QueueUrl":"https://eu-central-1.queue.amazonaws.com/123456789/test"
}</pre>
<hr>
<h3 id="h_442820800231528828585443">List all queues: aws-sqs-list-queues</h3>
<p>List all Amazon SQS queues.</p>
<h5>Command Example</h5>
<p><code>!aws-sqs-list-queues</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>sqs:ListQueues</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">queueNamePrefix</td>
<td style="width: 535px;">A string to use for filtering the list results. Only queues whose name begins with the specified string are returned. Queue names are case-sensitive.</td>
</tr>
<tr>
<td style="width: 179px;">queueOwnerAWSAccountId</td>
<td style="width: 535px;">The AWS account ID of the account that created the queue</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">AWS.SQS.Queues.QueueUrl</td>
<td style="width: 503px;">The URL of the queue</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "QueueUrl":"https://eu-central-1.queue.amazonaws.com/123456789/test"
   },
   {  
      "QueueUrl":"https://eu-central-1.queue.amazonaws.com/123456789/test2"
   }
]</pre>
<hr>
<h3 id="h_398305729441528828949972">Send a message: aws-sqs-send-message</h3>
<p>Send a message to an Amazon SQS queue.</p>
<h5>Command Example</h5>
<p><code>!aws-sqs-send-message queueUrl=https://eu-central-1.queue.amazonaws.com/123456789/test messageBody="test"</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>sqs:SendMessage</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">queueUrl</td>
<td style="width: 535px;">The URL of the Amazon SQS queue to which a message is sent</td>
</tr>
<tr>
<td style="width: 179px;">messageBody</td>
<td style="width: 535px;">The message to send (maximum string size is 256 KB)</td>
</tr>
<tr>
<td style="width: 179px;">delaySeconds</td>
<td style="width: 535px;">The length of time, in seconds, to delay a specific message. Valid values: 0 to 900. </td>
</tr>
<tr>
<td style="width: 179px;">messageGroupId</td>
<td style="width: 535px;">This parameter applies only to FIFO queues. The tag that specifies that a message belongs to a specific message group.</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">AWS.SQS.Queues.SentMessages.MD5OfMessageBody</td>
<td style="width: 503px;">An MD5 digest of the non-URL-encoded message attribute string</td>
</tr>
<tr>
<td style="width: 210px;">AWS.SQS.Queues.SentMessages.MD5OfMessageAttributes</td>
<td style="width: 503px;">An MD5 digest of the non-URL-encoded message attribute string</td>
</tr>
<tr>
<td style="width: 210px;">AWS.SQS.Queues.SentMessages.MessageId</td>
<td style="width: 503px;">An attribute containing the MessageId of the message sent to the queue</td>
</tr>
<tr>
<td style="width: 210px;">AWS.SQS.Queues.SentMessages.SequenceNumber</td>
<td style="width: 503px;">This parameter applies only to FIFO (first-in-first-out) queues. The large, non-consecutive number that Amazon SQS assigns to each message.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "MD5OfMessageBody":"098f6asdfbcd4621d3asd73cdsfade4e832627b4f6",
   "MessageId":"c54abasb01-c353-4810-a434-a9aadf233fa68f",
   "QueueUrl":"https://eu-central-1.queue.amazonaws.com/123456789/test"
}</pre>
<hr>
<h3 id="h_801821297701528829379275">Create a queue: aws-sqs-create-queue</h3>
<p>Create a queue in Amazon SQS.</p>
<h5>Command Example</h5>
<p><code>!aws-sqs-create-queue queueName=test3</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>sqs:CreateQueue</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">queueName</td>
<td style="width: 535px;">The name of the new queue. The following limits apply to this name: A queue name can have up to 80 characters. Valid values: alphanumeric characters, hyphens (- ), and underscores (_ ). A FIFO queue name must end with the .fifo suffix. Queue names are case-sensitive.</td>
</tr>
<tr>
<td style="width: 179px;">delaySeconds</td>
<td style="width: 535px;">The length of time, in seconds, to delay a specific message. Valid values: 0 to 900, the default is 0.</td>
</tr>
<tr>
<td style="width: 179px;">maximumMessageSize</td>
<td style="width: 535px;">The limit of how many bytes a message can contain before Amazon SQS rejects it. Valid values: An integer from 1,024 bytes (1 KiB) to 262,144 bytes (256 KiB). The default is 262,144 (256 KiB).</td>
</tr>
<tr>
<td style="width: 179px;">messageRetentionPeriod</td>
<td style="width: 535px;">The length of time, in seconds, for which Amazon SQS retains a message. Valid values: An integer from 60 seconds (1 minute) to 1,209,600 seconds (14 days). The default is 345,600 (4 days).</td>
</tr>
<tr>
<td style="width: 179px;">receiveMessageWaitTimeSeconds</td>
<td style="width: 535px;">The length of time, in seconds, for which a ReceiveMessage action waits for a message to arrive. Valid values: An integer from 0 to 20 (seconds). The default is 0.</td>
</tr>
<tr>
<td style="width: 179px;">visibilityTimeout</td>
<td style="width: 535px;">The visibility timeout for the queue. Valid values: An integer from 0 to 43,200 (12 hours). The default is 30.</td>
</tr>
<tr>
<td style="width: 179px;">kmsDataKeyReusePeriodSeconds</td>
<td style="width: 535px;">The length of time, in seconds, for which Amazon SQS can reuse a data key to encrypt or decrypt messages before calling AWS KMS again. An integer representing seconds, between 60 seconds (1 minute) and 86,400 seconds (24 hours). The default is 300 (5 minutes). A shorter time period provides better security but results in more calls to KMS which might incur charges after Free Tier.</td>
</tr>
<tr>
<td style="width: 179px;">kmsMasterKeyId</td>
<td style="width: 535px;">The ID of an AWS-managed customer master key (CMK) for Amazon SQS or a custom CMK</td>
</tr>
<tr>
<td style="width: 179px;">policy</td>
<td style="width: 535px;">The queue's policy. A valid AWS policy.</td>
</tr>
<tr>
<td style="width: 179px;">fifoQueue</td>
<td style="width: 535px;">Designates a queue as FIFO</td>
</tr>
<tr>
<td style="width: 179px;">contentBasedDeduplication</td>
<td style="width: 535px;">Enables content-based deduplication</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 63px; width: 734px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 224px;"><strong>Path</strong></td>
<td style="width: 489px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 224px;">AWS.SQS.Queues.QueueUrl</td>
<td style="width: 489px;">The URL of the created Amazon SQS queue</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "QueueUrl":"https://eu-central-1.queue.amazonaws.com/123456789/test3"
}</pre>
<hr>
<h3 id="h_4728900091011528829585308">Delete a queue: aws-sqs-delete-queue</h3>
<p>Deletes a queue from Amazon SQS.</p>
<h5>Command Example</h5>
<p><code>!aws-sqs-delete-queue queueUrl=https://eu-central-1.queue.amazonaws.com/123456789/test3</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>sqs:DeleteQueue</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">queueUrl</td>
<td style="width: 535px;">The URL of the Amazon SQS queue to delete</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>The Queue was deleted.</pre>
<hr>
<h3 id="h_1452318441361528867523193">Delete messages from a queue: aws-sqs-purge-queue</h3>
<p>Deletes messages from a specified queue in Amazon SQS.</p>
<h5>Command Example</h5>
<p><code>!aws-sqs-purge-queue queueUrl=aws-sqs-delete-queue queueUrl=https://eu-central-1.queue.amazonaws.com/123456789/test2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>sqs:PurgeQueue</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">queueUrl</td>
<td style="width: 535px;">The URL of the queue from which the PurgeQueue action deletes messages</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>The Queue was purged.</pre>