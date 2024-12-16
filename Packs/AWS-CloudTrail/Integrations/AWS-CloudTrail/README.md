Amazon Web Services CloudTrail.
This integration was integrated and tested with version 1.0.11 of AWS - CloudTrail.

## Configure AWS - CloudTrail in Cortex


| **Parameter** | **Required** |
| --- | --- |
| AWS Default Region | False |
| Role Arn | False |
| Role Session Name | False |
| Role Session Duration | False |
| Access Key | False |
| Secret Key | False |
| Access Key | False |
| Secret Key | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-cloudtrail-create-trail

***
Creates a trail that specifies the settings for delivery of log data to an Amazon S3 bucket. A maximum of five trails can exist in a region, irrespective of the region in which they were created.

#### Base Command

`aws-cloudtrail-create-trail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Specifies the name of the trail. | Required | 
| s3BucketName | Specifies the name of the Amazon S3 bucket designated for publishing log files. | Required | 
| s3KeyPrefix | Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery. | Optional | 
| snsTopicName | Specifies the name of the Amazon SNS topic defined for notification of log file delivery. | Optional | 
| includeGlobalServiceEvents | Specifies whether the trail is publishing events from global services such as IAM to the log files. Possible values are: True, False. | Optional | 
| isMultiRegionTrail | Specifies whether the trail is created in the current region or in all regions. The default is false. Possible values are: True, False. | Optional | 
| enableLogFileValidation | Specifies whether log file integrity validation is enabled. The default is false. Possible values are: True, False. | Optional | 
| cloudWatchLogsLogGroupArn | Specifies a log group name using an Amazon Resource Name (ARN), a unique identifier that represents the log group to which CloudTrail logs will be delivered. Not required unless you specify CloudWatchLogsRoleArn. | Optional | 
| cloudWatchLogsRoleArn | Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group. | Optional | 
| kmsKeyId | Specifies the KMS key ID to use to encrypt the logs delivered by CloudTrail. The value can be an alias name prefixed by "alias/", a fully specified ARN to an alias, a fully specified ARN to a key, or a globally unique identifier. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.CloudTrail.Trails.Name | string | Specifies the name of the trail. | 
| AWS.CloudTrail.Trails.S3BucketName | string | Specifies the name of the Amazon S3 bucket designated for publishing log files. | 
| AWS.CloudTrail.Trails.IncludeGlobalServiceEvents | boolean | Specifies whether the trail is publishing events from global services such as IAM to the log files. | 
| AWS.CloudTrail.Trails.IsMultiRegionTrail | boolean | Specifies whether the trail exists in one region or in all regions. | 
| AWS.CloudTrail.Trails.TrailARN | string | Specifies the ARN of the trail that was created. | 
| AWS.CloudTrail.Trails.LogFileValidationEnabled | boolean | Specifies whether log file integrity validation is enabled. | 
| AWS.CloudTrail.Trails.SnsTopicARN | string | Specifies the ARN of the Amazon SNS topic that CloudTrail uses to send notifications when log files are delivered. | 
| AWS.CloudTrail.Trails.S3KeyPrefix | string | pecifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery. | 
| AWS.CloudTrail.Trails.CloudWatchLogsLogGroupArn | string | Specifies the Amazon Resource Name \(ARN\) of the log group to which CloudTrail logs will be delivered. | 
| AWS.CloudTrail.Trails.CloudWatchLogsRoleArn | string | Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group. | 
| AWS.CloudTrail.Trails.KmsKeyId | string | Specifies the KMS key ID that encrypts the logs delivered by CloudTrail. | 
| AWS.CloudTrail.Trails.HomeRegion | string | The region in which the trail was created. | 

### aws-cloudtrail-delete-trail

***
Deletes a trail. This operation must be called from the region in which the trail was created. DeleteTrail cannot be called on the shadow trails (replicated trails in other regions) of a trail that is enabled in all regions.

#### Base Command

`aws-cloudtrail-delete-trail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Specifies the name or the CloudTrail ARN of the trail to be deleted. The format of a trail ARN is: arn:aws:cloudtrail:us-east-1:123456789012:trail/MyTrail. | Required | 

#### Context Output

There is no context output for this command.
### aws-cloudtrail-describe-trails

***
Retrieves settings for the trail associated with the current region for your account.

#### Base Command

`aws-cloudtrail-describe-trails`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| trailNameList | Specifies a list of trail names, trail ARNs, or both, of the trails to describe. If an empty list is specified, information for the trail in the current region is returned. | Optional | 
| includeShadowTrails | Specifies whether to include shadow trails in the response. A shadow trail is the replication in a region of a trail that was created in a different region. The default is true. Possible values are: True, False. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.CloudTrail.Trails.Name | string | Name of the trail set by calling CreateTrail. | 
| AWS.CloudTrail.Trails.S3BucketName | string | Name of the Amazon S3 bucket into which CloudTrail delivers your trail files. | 
| AWS.CloudTrail.Trails.S3KeyPrefix | string | Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery. | 
| AWS.CloudTrail.Trails.SnsTopicARN | string | Specifies the ARN of the Amazon SNS topic that CloudTrail uses to send notifications when log files are delivered. | 
| AWS.CloudTrail.Trails.IncludeGlobalServiceEvents | boolean | Set to True to include AWS API calls from AWS global services such as IAM. Otherwise, False. | 
| AWS.CloudTrail.Trails.IsMultiRegionTrail | boolean | Specifies whether the trail belongs only to one region or exists in all regions. | 
| AWS.CloudTrail.Trails.HomeRegion | string | The region in which the trail was created. | 
| AWS.CloudTrail.Trails.TrailARN | string | Specifies the ARN of the trail. | 
| AWS.CloudTrail.Trails.LogFileValidationEnabled | boolean | Specifies whether log file validation is enabled. | 
| AWS.CloudTrail.Trails.CloudWatchLogsLogGroupArn | string | Specifies an Amazon Resource Name \(ARN\), a unique identifier that represents the log group to which CloudTrail logs will be delivered. | 
| AWS.CloudTrail.Trails.CloudWatchLogsRoleArn | string | Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group. | 
| AWS.CloudTrail.KmsKeyId | string | Specifies the KMS key ID that encrypts the logs delivered by CloudTrail. | 
| AWS.CloudTrail.HasCustomEventSelectors | boolean | Specifies if the trail has custom event selectors. | 

### aws-cloudtrail-update-trail

***
Updates the settings that specify delivery of log files. Changes to a trail do not require stopping the CloudTrail service.

#### Base Command

`aws-cloudtrail-update-trail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Specifies the name of the trail or trail ARN. | Required | 
| s3BucketName | Specifies the name of the Amazon S3 bucket designated for publishing log files. | Optional | 
| s3KeyPrefix | Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery. | Optional | 
| snsTopicName | Specifies the name of the Amazon SNS topic defined for notification of log file delivery. | Optional | 
| includeGlobalServiceEvents | Specifies whether the trail is publishing events from global services such as IAM to the log files. | Optional | 
| isMultiRegionTrail | Specifies whether the trail applies only to the current region or to all regions. The default is false. If the trail exists only in the current region and this value is set to true, shadow trails (replications of the trail) will be created in the other regions. If the trail exists in all regions and this value is set to false, the trail will remain in the region where it was created, and its shadow trails in other regions will be deleted. | Optional | 
| enableLogFileValidation | Specifies whether log file validation is enabled. The default is false. | Optional | 
| cloudWatchLogsLogGroupArn | Specifies a log group name using an Amazon Resource Name (ARN), a unique identifier that represents the log group to which CloudTrail logs will be delivered. Not required unless you specify CloudWatchLogsRoleArn. | Optional | 
| cloudWatchLogsRoleArn | Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group. | Optional | 
| kmsKeyId | Specifies the KMS key ID to use to encrypt the logs delivered by CloudTrail. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.CloudTrail.Trails.Name | string | Specifies the name of the trail. | 
| AWS.CloudTrail.Trails.S3BucketName | string | Specifies the name of the Amazon S3 bucket designated for publishing log files. | 
| AWS.CloudTrail.Trails.IncludeGlobalServiceEvents | boolean | Specifies whether the trail is publishing events from global services such as IAM to the log files. | 
| AWS.CloudTrail.Trails.IsMultiRegionTrail | boolean | Specifies whether the trail exists in one region or in all regions. | 
| AWS.CloudTrail.Trails.TrailARN | string | Specifies the ARN of the trail that was created. | 
| AWS.CloudTrail.Trails.LogFileValidationEnabled | boolean | Specifies whether log file integrity validation is enabled. | 
| AWS.CloudTrail.Trails.SnsTopicARN | string | Specifies the ARN of the Amazon SNS topic that CloudTrail uses to send notifications when log files are delivered. | 
| AWS.CloudTrail.Trails.S3KeyPrefix | string | pecifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery. | 
| AWS.CloudTrail.Trails.CloudWatchLogsLogGroupArn | string | Specifies the Amazon Resource Name \(ARN\) of the log group to which CloudTrail logs will be delivered. | 
| AWS.CloudTrail.Trails.CloudWatchLogsRoleArn | string | Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group. | 
| AWS.CloudTrail.Trails.KmsKeyId | string | Specifies the KMS key ID that encrypts the logs delivered by CloudTrail. | 
| AWS.CloudTrail.Trails.HomeRegion | string | The region in which the trail was created. | 

### aws-cloudtrail-start-logging

***
Starts the recording of AWS API calls and log file delivery for a trail. For a trail that is enabled in all regions, this operation must be called from the region in which the trail was created. This operation cannot be called on the shadow trails (replicated trails in other regions) of a trail that is enabled in all regions.

#### Base Command

`aws-cloudtrail-start-logging`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Specifies the name or the CloudTrail ARN of the trail for which CloudTrail logs AWS API calls. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-cloudtrail-stop-logging

***
Suspends the recording of AWS API calls and log file delivery for the specified trail. Under most circumstances, there is no need to use this action. You can update a trail without stopping it first. This action is the only way to stop recording. For a trail enabled in all regions, this operation must be called from the region in which the trail was created, or an InvalidHomeRegionException will occur. This operation cannot be called on the shadow trails (replicated trails in other regions) of a trail enabled in all regions.

#### Base Command

`aws-cloudtrail-stop-logging`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Specifies the name or the CloudTrail ARN of the trail for which CloudTrail logs AWS API calls. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-cloudtrail-lookup-events

***
Looks up API activity events captured by CloudTrail that create, update, or delete resources in your account. Events for a region can be looked up for the times in which you had CloudTrail turned on in that region during the last seven days.

#### Base Command

`aws-cloudtrail-lookup-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attributeKey | Specifies an attribute on which to filter the events returned. Possible values are: AccessKeyId, EventId, EventName, Username, ResourceType, ResourceName, EventSource, ReadOnly. | Required | 
| attributeValue | Specifies a value for the specified AttributeKey. | Required | 
| startTime | Specifies that only events that occur after or at the specified time are returned. | Optional | 
| endTime | Specifies that only events that occur before or at the specified time are returned. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.CloudTrail.Events.EventId | string | The CloudTrail ID of the event returned. | 
| AWS.CloudTrail.Events.EventName | string | The name of the event returned. | 
| AWS.CloudTrail.Events.EventTime | date | The date and time of the event returned. | 
| AWS.CloudTrail.Events.EventSource | string | The AWS service that the request was made to. | 
| AWS.CloudTrail.Events.Username | string | A user name or role name of the requester that called the API in the event returned. | 
| AWS.CloudTrail.Events.ResourceName | string | The type of a resource referenced by the event returned. When the resource type cannot be determined, null is returned. Some examples of resource types are: Instance for EC2, Trail for CloudTrail, DBInstance for RDS, and AccessKey for IAM.  | 
| AWS.CloudTrail.Events.ResourceType | string | The name of the resource referenced by the event returned. These are user-created names whose values will depend on the environment. For example, the resource name might be "auto-scaling-test-group" for an Auto Scaling Group or "i-1234567" for an EC2 Instance. | 
| AWS.CloudTrail.Events.CloudTrailEvent | string | A JSON string that contains a representation of the event returned. | 

### aws-cloudtrail-get-trail-status

***
Returns a JSON-formatted list of information about the specified trail. Fields include information on delivery errors, Amazon SNS and Amazon S3 errors, and start and stop logging times for each trail.

#### Base Command

`aws-cloudtrail-get-trail-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| trailNameList | Specifies the names of multiple trails. | Optional | 
| region | Specifies the region of the trail. | Required | 
| roleArn | The The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| name | Specifies the name of the trail. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.CloudTrail.TrailStatus.IsLogging | boolean | Whether the CloudTrail trail is currently logging Amazon Web Services API calls. | 
| AWS.CloudTrail.TrailStatus.LatestDeliveryError | string | Displays any Amazon S3 error that CloudTrail encountered when attempting to deliver log files to the designated bucket. | 
| AWS.CloudTrail.TrailStatus.LatestNotificationError | string | Displays any Amazon SNS error that CloudTrail encountered when attempting to send a notification. | 
| AWS.CloudTrail.TrailStatus.LatestDeliveryTime | date | Specifies the date and time that CloudTrail last delivered log files to an account’s Amazon S3 bucket. | 
| AWS.CloudTrail.TrailStatus.LatestNotificationTime | date | Specifies the date and time of the most recent Amazon SNS notification that CloudTrail has written a new log file to an account’s Amazon S3 bucket. | 
| AWS.CloudTrail.TrailStatus.StartLoggingTime | date | Specifies the most recent date and time when CloudTrail started recording API calls for an Amazon Web Services account. | 
| AWS.CloudTrail.TrailStatus.StopLoggingTime | date | Specifies the most recent date and time when CloudTrail stopped recording API calls for an Amazon Web Services account. | 
| AWS.CloudTrail.TrailStatus.LatestCloudWatchLogsDeliveryError | string | Displays any CloudWatch Logs error that CloudTrail encountered when attempting to deliver logs to CloudWatch Logs. | 
| AWS.CloudTrail.TrailStatus.LatestCloudWatchLogsDeliveryTime | date | Displays the most recent date and time when CloudTrail delivered logs to CloudWatch Logs. | 
| AWS.CloudTrail.TrailStatus.LatestDigestDeliveryTime | date | Specifies the date and time that CloudTrail last delivered a digest file to an account’s Amazon S3 bucket. | 
| AWS.CloudTrail.TrailStatus.LatestDigestDeliveryError | string | Displays any Amazon S3 error that CloudTrail encountered when attempting to deliver a digest file to the designated bucket. | 