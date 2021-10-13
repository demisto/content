<!-- HTML_DOC -->
<p>AWS CloudTrail is a service that enables governance, compliance, operational auditing, and risk auditing of your AWS account. With CloudTrail, you can log, continuously monitor, and retain account activity related to actions across your AWS infrastructure. CloudTrail provides event history of your AWS account activity, including actions taken through the AWS Management Console, AWS SDKs, command line tools, and other AWS services. This event history simplifies security analysis, resource change tracking, and troubleshooting. For more information, see the <a href="https://aws.amazon.com/cloudtrail/" target="_blank" rel="noopener">AWS CloudTrail documentation</a>.</p>
<h2>Configure AWS CloudTrail on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for AWS - CloudTrail.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>Default Region</strong>:</li>
<li><strong>Role Arn</strong></li>
<li><strong>Role Session Name</strong></li>
<li><strong>Role Session Duration</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_589060726551537170698921">Create a trail: aws-cloudtrail-create-trail</a></li>
<li><a href="#h_3520194191261537170708997">Delete a trail: aws-cloudtrail-delete-trail</a></li>
<li><a href="#h_790727151951537170714578">Get the settings of a trail: aws-cloudtrail-describe-trails</a></li>
<li><a href="#h_550289152641537170720170">Update a trail: aws-cloudtrail-update-trail</a></li>
<li><a href="#h_4634425373321537170726697">Start recording logs: aws-cloudtrail-start-logging</a></li>
<li><a href="#h_1455390123981537170732135">Stop recording logs: aws-cloudtrail-stop-logging</a></li>
<li><a href="#h_2415424384631537170737396">Search API activity events: aws-cloudtrail-lookup-events</a></li>
</ol>
<h3 id="h_589060726551537170698921">1. Create a trail</h3>
<hr>
<p>Creates a trail that specifies the settings for delivery of log data to an Amazon S3 bucket. A maximum of five trails can exist in a region, irrespective of the region in which they were created.</p>
<h5>Base Command</h5>
<p><code>aws-cloudtrail-create-trail</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 203px;"><strong>Argument Name</strong></th>
<th style="width: 434px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 203px;">name</td>
<td style="width: 434px;">Specifies the name of the trail</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 203px;">s3BucketName</td>
<td style="width: 434px;">Specifies the name of the Amazon S3 bucket designated for publishing log files</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 203px;">s3KeyPrefix</td>
<td style="width: 434px;">Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 203px;">snsTopicName</td>
<td style="width: 434px;">Specifies the name of the Amazon SNS topic defined for notification of log file delivery</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 203px;">includeGlobalServiceEvents</td>
<td style="width: 434px;">Specifies whether the trail is publishing events from global services, such as IAM, to the log files</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 203px;">isMultiRegionTrail</td>
<td style="width: 434px;">Specifies whether the trail is created in the current region or in all regions. The default is false.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 203px;">enableLogFileValidation</td>
<td style="width: 434px;">Specifies whether log file integrity validation is enabled. The default is false.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 203px;">cloudWatchLogsLogGroupArn</td>
<td style="width: 434px;">Specifies a log group name using an Amazon Resource Name (ARN), a unique identifier that represents the log group to which CloudTrail logs will be delivered. Not required unless you specify CloudWatchLogsRoleArn.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 203px;">cloudWatchLogsRoleArn</td>
<td style="width: 434px;">Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 203px;">kmsKeyId</td>
<td style="width: 434px;">Specifies the KMS key ID to use to encrypt the logs delivered by CloudTrail. The value can be an alias name prefixed by "alias/", a fully specified ARN to an alias, a fully specified ARN to a key, or a globally unique identifier.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 203px;">region</td>
<td style="width: 434px;">The AWS Region, if not specified the default region will be used</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 203px;">roleArn</td>
<td style="width: 434px;">The Amazon Resource Name (ARN) of the role to assume</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 203px;">roleSessionName</td>
<td style="width: 434px;">An identifier for the assumed role session</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 203px;">roleSessionDuration</td>
<td style="width: 434px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 364px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 291px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.Name</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the name of the trail</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.S3BucketName</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the name of the Amazon S3 bucket designated for publishing log files</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.IncludeGlobalServiceEvents</td>
<td style="width: 53px;">boolean</td>
<td style="width: 291px;">Specifies whether the trail is publishing events from global services such as IAM to the log files</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.IsMultiRegionTrail</td>
<td style="width: 53px;">boolean</td>
<td style="width: 291px;">Specifies whether the trail exists in one region or in all regions</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.TrailARN</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the ARN of the trail that was created</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.LogFileValidationEnabled</td>
<td style="width: 53px;">boolean</td>
<td style="width: 291px;">Specifies whether log file integrity validation is enabled</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.SnsTopicARN</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the ARN of the Amazon SNS topic that CloudTrail uses to send notifications when log files are delivered</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.S3KeyPrefix</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.CloudWatchLogsLogGroupArn</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the Amazon Resource Name (ARN) of the log group to which CloudTrail logs will be delivered</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.CloudWatchLogsRoleArn</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.KmsKeyId</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the KMS key ID that encrypts the logs delivered by CloudTrail</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.HomeRegion</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">The region in which the trail was created</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p>!aws-cloudtrail-create-trail name=test s3BucketName=test</p>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/44986554-66339300-af84-11e8-8498-85e2d5cc970e.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/44986554-66339300-af84-11e8-8498-85e2d5cc970e.png" alt="image" width="750" height="334"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/44984342-af7fe480-af7c-11e8-8de7-14d95b1c438d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/44984342-af7fe480-af7c-11e8-8de7-14d95b1c438d.png" alt="image" width="751" height="399"></a></p>
<h3 id="h_3520194191261537170708997">2. Delete a trail</h3>
<hr>
<p>Deletes a trail. This operation must be called from the region in which the trail was created. DeleteTrail cannot be called on the shadow trails (replicated trails in other regions) of a trail that is enabled in all regions.</p>
<h5>Base Command</h5>
<p><code>aws-cloudtrail-delete-trail</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 141px;"><strong>Argument Name</strong></th>
<th style="width: 496px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">name</td>
<td style="width: 496px;">Specifies the name or the CloudTrail ARN of the trail to be deleted. The format of a trail ARN is: arn:aws:cloudtrail:us-east-1:123456789012:trail/MyTrail</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p>!aws-cloudtrail-delete-trail name=test</p>
<h5>Human Readable Output</h5>
<h5><a href="https://user-images.githubusercontent.com/34302832/44986642-c1fe1c00-af84-11e8-8bd8-5e9327750955.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/44986642-c1fe1c00-af84-11e8-8bd8-5e9327750955.png" alt="image" width="753" height="73"></a></h5>
<h3 id="h_790727151951537170714578">3. Get the settings of a trail</h3>
<hr>
<p>Retrieves settings for the trail associated with the current region for your account.</p>
<h5>Base Command</h5>
<p><code>aws-cloudtrail-describe-trails</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 148px;"><strong>Argument Name</strong></th>
<th style="width: 489px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">trailNameList</td>
<td style="width: 489px;">Specifies a list of trail names, trail ARNs, or both, of the trails to describe. If an empty list is specified, information for the trail in the current region is returned.</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 148px;">includeShadowTrails</td>
<td style="width: 489px;">Specifies whether to include shadow trails in the response. A shadow trail is the replication in a region of a trail that was created in a different region. The default is "true".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">region</td>
<td style="width: 489px;">The AWS Region, if not specified the default region will be used</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">roleArn</td>
<td style="width: 489px;">The Amazon Resource Name (ARN) of the role to assume</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">roleSessionName</td>
<td style="width: 489px;">An identifier for the assumed role session</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">roleSessionDuration</td>
<td style="width: 489px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 364px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 291px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.Name</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Name of the trail set by calling CreateTrail</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.S3BucketName</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Name of the Amazon S3 bucket into which CloudTrail delivers your trail files</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.S3KeyPrefix</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.SnsTopicARN</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the ARN of the Amazon SNS topic that CloudTrail uses to send notifications when log files are delivered</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.IncludeGlobalServiceEvents</td>
<td style="width: 53px;">boolean</td>
<td style="width: 291px;">Set to "True" to include AWS API calls from AWS global services such as IAM. Otherwise, "False".</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.IsMultiRegionTrail</td>
<td style="width: 53px;">boolean</td>
<td style="width: 291px;">Specifies whether the trail belongs only to one region or exists in all regions</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.HomeRegion</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">The region in which the trail was created</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.TrailARN</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the ARN of the trail</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.LogFileValidationEnabled</td>
<td style="width: 53px;">boolean</td>
<td style="width: 291px;">Specifies whether log file validation is enabled</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.CloudWatchLogsLogGroupArn</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies an Amazon Resource Name (ARN), a unique identifier that represents the log group to which CloudTrail logs will be delivered</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.Trails.CloudWatchLogsRoleArn</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.KmsKeyId</td>
<td style="width: 53px;">string</td>
<td style="width: 291px;">Specifies the KMS key ID that encrypts the logs delivered by CloudTrail</td>
</tr>
<tr>
<td style="width: 364px;">AWS.CloudTrail.HasCustomEventSelectors</td>
<td style="width: 53px;">boolean</td>
<td style="width: 291px;">Specifies if the trail has custom event selectors</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p>!aws-cloudtrail-describe-trails</p>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/44986869-6f712f80-af85-11e8-85c4-a7b5935ce2b8.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/44986869-6f712f80-af85-11e8-85c4-a7b5935ce2b8.png" alt="image" width="750" height="364"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/44986812-42bd1800-af85-11e8-8eaf-85313efcb5d0.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/44986812-42bd1800-af85-11e8-8eaf-85313efcb5d0.png" alt="image" width="750" height="376"></a></p>
<h3 id="h_550289152641537170720170">4. Update a trail</h3>
<hr>
<p>Updates the settings that specify delivery of log files. Changes to a trail do not require stopping the CloudTrail service.</p>
<h5>Base Command</h5>
<p><code>aws-cloudtrail-update-trail</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 211px;"><strong>Argument Name</strong></th>
<th style="width: 426px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 211px;">name</td>
<td style="width: 426px;">Specifies the name of the trail or trail ARN</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 211px;">s3BucketName</td>
<td style="width: 426px;">Specifies the name of the Amazon S3 bucket designated for publishing log files</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211px;">s3KeyPrefix</td>
<td style="width: 426px;">Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211px;">snsTopicName</td>
<td style="width: 426px;">Specifies the name of the Amazon SNS topic defined for notification of log file delivery</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211px;">includeGlobalServiceEvents</td>
<td style="width: 426px;">Specifies whether the trail is publishing events from global services such as IAM to the log files</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211px;">isMultiRegionTrail</td>
<td style="width: 426px;">Specifies whether the trail applies only to the current region or to all regions. The default is false. If the trail exists only in the current region and this value is set to true, shadow trails (replications of the trail) will be created in the other regions. If the trail exists in all regions and this value is set to false, the trail will remain in the region where it was created, and its shadow trails in other regions will be deleted.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211px;">enableLogFileValidation</td>
<td style="width: 426px;">Specifies whether log file validation is enabled. The default is false.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211px;">cloudWatchLogsLogGroupArn</td>
<td style="width: 426px;">Specifies a log group name using an Amazon Resource Name (ARN), a unique identifier that represents the log group to which CloudTrail logs will be delivered. Not required unless you specify CloudWatchLogsRoleArn.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211px;">cloudWatchLogsRoleArn</td>
<td style="width: 426px;">Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211px;">kmsKeyId</td>
<td style="width: 426px;">Specifies the KMS key ID to use to encrypt the logs delivered by CloudTrail</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211px;">region</td>
<td style="width: 426px;">The AWS Region, if not specified the default region will be used</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211px;">roleArn</td>
<td style="width: 426px;">The Amazon Resource Name (ARN) of the role to assume</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211px;">roleSessionName</td>
<td style="width: 426px;">An identifier for the assumed role session</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211px;">roleSessionDuration</td>
<td style="width: 426px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 366px;"><strong>Path</strong></th>
<th style="width: 51px;"><strong>Type</strong></th>
<th style="width: 291px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 366px;">AWS.CloudTrail.Trails.Name</td>
<td style="width: 51px;">string</td>
<td style="width: 291px;">Specifies the name of the trail</td>
</tr>
<tr>
<td style="width: 366px;">AWS.CloudTrail.Trails.S3BucketName</td>
<td style="width: 51px;">string</td>
<td style="width: 291px;">Specifies the name of the Amazon S3 bucket designated for publishing log files</td>
</tr>
<tr>
<td style="width: 366px;">AWS.CloudTrail.Trails.IncludeGlobalServiceEvents</td>
<td style="width: 51px;">boolean</td>
<td style="width: 291px;">Specifies whether the trail is publishing events from global services such as IAM to the log files</td>
</tr>
<tr>
<td style="width: 366px;">AWS.CloudTrail.Trails.IsMultiRegionTrail</td>
<td style="width: 51px;">boolean</td>
<td style="width: 291px;">Specifies whether the trail exists in one region or in all regions</td>
</tr>
<tr>
<td style="width: 366px;">AWS.CloudTrail.Trails.TrailARN</td>
<td style="width: 51px;">string</td>
<td style="width: 291px;">Specifies the ARN of the trail that was created</td>
</tr>
<tr>
<td style="width: 366px;">AWS.CloudTrail.Trails.LogFileValidationEnabled</td>
<td style="width: 51px;">boolean</td>
<td style="width: 291px;">Specifies whether log file integrity validation is enabled</td>
</tr>
<tr>
<td style="width: 366px;">AWS.CloudTrail.Trails.SnsTopicARN</td>
<td style="width: 51px;">string</td>
<td style="width: 291px;">Specifies the ARN of the Amazon SNS topic that CloudTrail uses to send notifications when log files are delivered</td>
</tr>
<tr>
<td style="width: 366px;">AWS.CloudTrail.Trails.S3KeyPrefix</td>
<td style="width: 51px;">string</td>
<td style="width: 291px;">Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery</td>
</tr>
<tr>
<td style="width: 366px;">AWS.CloudTrail.Trails.CloudWatchLogsLogGroupArn</td>
<td style="width: 51px;">string</td>
<td style="width: 291px;">Specifies the Amazon Resource Name (ARN) of the log group to which CloudTrail logs will be delivered</td>
</tr>
<tr>
<td style="width: 366px;">AWS.CloudTrail.Trails.CloudWatchLogsRoleArn</td>
<td style="width: 51px;">string</td>
<td style="width: 291px;">Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group</td>
</tr>
<tr>
<td style="width: 366px;">AWS.CloudTrail.Trails.KmsKeyId</td>
<td style="width: 51px;">string</td>
<td style="width: 291px;">Specifies the KMS key ID that encrypts the logs delivered by CloudTrail</td>
</tr>
<tr>
<td style="width: 366px;">AWS.CloudTrail.Trails.HomeRegion</td>
<td style="width: 51px;">string</td>
<td style="width: 291px;">The region in which the trail was created</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p>!aws-cloudtrail-update-trail name=test isMultiRegionTrail=true</p>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/44986869-6f712f80-af85-11e8-85c4-a7b5935ce2b8.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/44986869-6f712f80-af85-11e8-85c4-a7b5935ce2b8.png" alt="image" width="748" height="363"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/44987057-240b5100-af86-11e8-923c-8865248dce61.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/44987057-240b5100-af86-11e8-923c-8865248dce61.png" alt="image" width="756" height="379"></a></p>
<h3 id="h_4634425373321537170726697">5. Start recording logs</h3>
<hr>
<p>Starts the recording of AWS API calls and log file delivery for a trail. For a trail that is enabled in all regions, this operation must be called from the region in which the trail was created. This operation cannot be called on the shadow trails (replicated trails in other regions) of a trail that is enabled in all regions.</p>
<h5>Base Command</h5>
<p><code>aws-cloudtrail-start-logging</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 150px;"><strong>Argument Name</strong></th>
<th style="width: 487px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 150px;">name</td>
<td style="width: 487px;">Specifies the name or the CloudTrail ARN of the trail for which CloudTrail logs AWS API calls</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 150px;">region</td>
<td style="width: 487px;">The AWS Region, if not specified the default region will be used</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 150px;">roleArn</td>
<td style="width: 487px;">The Amazon Resource Name (ARN) of the role to assume</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 150px;">roleSessionName</td>
<td style="width: 487px;">An identifier for the assumed role session</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 150px;">roleSessionDuration</td>
<td style="width: 487px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p>!aws-cloudtrail-start-logging name=test</p>
<h5>Context Example</h5>
<p>There is no context output for this command.</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/44987148-6e8ccd80-af86-11e8-9e20-ccac11087749.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/44987148-6e8ccd80-af86-11e8-9e20-ccac11087749.png" alt="image" width="748" height="102"></a></p>
<h3 id="h_1455390123981537170732135">6. Stop recording logs</h3>
<hr>
<p>Suspends the recording of AWS API calls and log file delivery for the specified trail. Under most circumstances, there is no need to use this action. You can update a trail without stopping it first. This action is the only way to stop recording. For a trail enabled in all regions, this operation must be called from the region in which the trail was created, or an InvalidHomeRegionException will occur. This operation cannot be called on the shadow trails (replicated trails in other regions) of a trail enabled in all regions.</p>
<h5>Base Command</h5>
<p><code>aws-cloudtrail-stop-logging</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 488px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">name</td>
<td style="width: 488px;">Specifies the name or the CloudTrail ARN of the trail for which CloudTrail logs AWS API calls</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 149px;">region</td>
<td style="width: 488px;">The AWS Region, if not specified the default region will be used</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">roleArn</td>
<td style="width: 488px;">The Amazon Resource Name (ARN) of the role to assume</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">roleSessionName</td>
<td style="width: 488px;">An identifier for the assumed role session</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">roleSessionDuration</td>
<td style="width: 488px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p>!aws-cloudtrail-stop-logging name=test</p>
<h5>Context Example</h5>
<p>There is no context output for this command.</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/44987179-9419d700-af86-11e8-9283-1c50b1275ff1.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/44987179-9419d700-af86-11e8-9283-1c50b1275ff1.png" alt="image"></a></p>
<h3 id="h_2415424384631537170737396">7. Search API activity events</h3>
<hr>
<p>Looks up API activity events captured by CloudTrail that create, update, or delete resources in your account. Events for a region can be looked up for the times in which you had CloudTrail turned on in that region during the last seven days.</p>
<h5>Base Command</h5>
<p><code>aws-cloudtrail-lookup-events</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 491px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">attributeKey</td>
<td style="width: 491px;">Specifies an attribute on which to filter the returned events</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">attributeValue</td>
<td style="width: 491px;">Specifies a value for the specified <em>AttributeKey</em>
</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">startTime</td>
<td style="width: 491px;">Specifies that only events that occur on or after the specified time are returned</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">endTime</td>
<td style="width: 491px;">Specifies that only events that occur on or before the specified time are returned</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">region</td>
<td style="width: 491px;">The AWS Region, if not specified the default region will be used</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">roleArn</td>
<td style="width: 491px;">The Amazon Resource Name (ARN) of the role to assume</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">roleSessionName</td>
<td style="width: 491px;">An identifier for the assumed role session</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">roleSessionDuration</td>
<td style="width: 491px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 318px;"><strong>Path</strong></th>
<th style="width: 37px;"><strong>Type</strong></th>
<th style="width: 353px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 318px;">AWS.CloudTrail.Trails.Events.EventId</td>
<td style="width: 37px;">string</td>
<td style="width: 353px;">The CloudTrail ID of the returned event</td>
</tr>
<tr>
<td style="width: 318px;">AWS.CloudTrail.Trails.Events.EventName</td>
<td style="width: 37px;">string</td>
<td style="width: 353px;">The name of the returned event</td>
</tr>
<tr>
<td style="width: 318px;">AWS.CloudTrail.Trails.Events.EventTime</td>
<td style="width: 37px;">date</td>
<td style="width: 353px;">The date and time of the returned event</td>
</tr>
<tr>
<td style="width: 318px;">AWS.CloudTrail.Trails.Events.EventSource</td>
<td style="width: 37px;">string</td>
<td style="width: 353px;">The AWS service that the request was made to</td>
</tr>
<tr>
<td style="width: 318px;">AWS.CloudTrail.Trails.Events.Username</td>
<td style="width: 37px;">string</td>
<td style="width: 353px;">User name or role name of the requester that called the API in the event returned</td>
</tr>
<tr>
<td style="width: 318px;">AWS.CloudTrail.Trails.Events.ResourceName</td>
<td style="width: 37px;">string</td>
<td style="width: 353px;">The type of a resource referenced by the event returned. When the resource type cannot be determined, null is returned. Some examples of resource types are: Instance for EC2, Trail for CloudTrail, DBInstance for RDS, and AccessKey for IAM.</td>
</tr>
<tr>
<td style="width: 318px;">AWS.CloudTrail.Trails.Events.ResourceType</td>
<td style="width: 37px;">string</td>
<td style="width: 353px;">The name of the resource referenced by the event returned. These are user-created names whose values will depend on the environment. For example, the resource name might be "auto-scaling-test-group" for an Auto Scaling Group or "i-1234567" for an EC2 Instance.</td>
</tr>
<tr>
<td style="width: 318px;">AWS.CloudTrail.Trails.Events.CloudTrailEvent</td>
<td style="width: 37px;">string</td>
<td style="width: 353px;">A JSON string that contains a representation of the returned event</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p>!aws-cloudtrail-lookup-events attributeKey=EventName attributeValue=StartLogging</p>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/44987458-916bb180-af87-11e8-8bdf-4167d9183df9.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/44987458-916bb180-af87-11e8-8bdf-4167d9183df9.png" alt="image" width="750" height="1020"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/44987322-28843980-af87-11e8-9d91-1867808b90c4.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/44987322-28843980-af87-11e8-9d91-1867808b90c4.png" alt="image" width="753" height="223"></a></p>