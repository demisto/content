Support for AWS cloud
This integration was integrated and tested with version 1.0.0 of AWS.

## Configure AWS in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Main Role | Main Role to be used for authentication e.g. 'PowerUserAccess' | False |
| Deafult AWS Account ID | AWS Account ID used for running integration test |  |
| Role Session Name | Role session name to be used for authentication |  |
| Role Session Duration | Max role session duration | False |
| Default AWS Access Key ID | AWS Access Key ID used for authentication when role-based authentication is not available. Must be used together with 'Default AWS Secret Access Key'. If provided, these credentials will be used as a fallback when role assumption fails. | False |
| Default AWS Secret Access Key | AWS Secret Access Key used for authentication when role-based authentication is not available. Must be used together with 'Default AWS Access Key ID'. If provided, these credentials will be used as a fallback when role assumption fails. | False |
| Password |  | False |
| Default AWS region. | The AWS region to use for API requests when a region is not explicitly specified in a command. This serves as the default region for operations across all AWS service-specific commands. |  |
| Timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| PrivateLink service URL. |  | False |
| STS PrivateLink URL. |  | False |
| AWS STS Regional Endpoints | Sets the AWS_STS_REGIONAL_ENDPOINTS environment variable to specify the AWS STS endpoint resolution logic. By default, this option is set to “legacy” in AWS. Leave empty if the environment variable is already set using server configuration. | False |
| Role name for cross-organization account access | The role name used to access accounts in the organization. This role name must exist in the accounts provided in "AWS Organization accounts" and be assumable with the credentials provided. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-s3-public-access-block-update

***
Creates or modifies the PublicAccessBlock configuration for an Amazon S3 bucket.

#### Base Command

`aws-s3-public-access-block-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. | Required |
| bucket | The name of the Amazon S3 bucket. | Required |
| block_public_acls | Specifies whether Amazon S3 should block public access control lists (ACLs) for this bucket and objects in this bucket. Possible values are: true, false. | Optional |
| ignore_public_acls | Specifies whether Amazon S3 should ignore public ACLs for this bucket and objects in this bucket. Possible values are: true, false. | Optional |
| block_public_policy | Specifies whether Amazon S3 should block public bucket policies for this bucket. Possible values are: true, false. | Optional |
| restrict_public_buckets | Specifies whether Amazon S3 should restrict public bucket policies for this bucket. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

### aws-iam-account-password-policy-get

***
Get AWS account password policy.

#### Base Command

`aws-iam-account-password-policy-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.PasswordPolicy.MinimumPasswordLength | number | Minimum length to require for IAM user passwords. |
| AWS.IAM.PasswordPolicy.RequireSymbols | boolean | Specifies whether IAM user passwords must contain at least one of the symbols. |
| AWS.IAM.PasswordPolicy.RequireNumbers | boolean | Specifies whether IAM user passwords must contain at least one numeric character \(0 to 9\). |
| AWS.IAM.PasswordPolicy.RequireUppercaseCharacters | boolean | Specifies whether IAM user passwords must contain at least one uppercase character \(A to Z\). |
| AWS.IAM.PasswordPolicy.RequireLowercaseCharacters | boolean | Specifies whether IAM user passwords must contain at least one lowercase character \(a to z\). |
| AWS.IAM.PasswordPolicy.AllowUsersToChangePassword | boolean | Specifies whether IAM users are allowed to change their own password. |
| AWS.IAM.PasswordPolicy.ExpirePasswords | boolean | Indicates whether passwords in the account expire. |
| AWS.IAM.PasswordPolicy.MaxPasswordAge | number | The number of days that an IAM user password is valid. |
| AWS.IAM.PasswordPolicy.PasswordReusePrevention | number | Specifies the number of previous passwords that IAM users are prevented from reusing. |
| AWS.IAM.PasswordPolicy.HardExpiry | boolean | Specifies whether IAM users are prevented from setting a new password via the Amazon Web Services Management Console after their password has expired. |

### aws-ec2-instance-metadata-options-modify

***
Modify the EC2 instance metadata parameters on a running or stopped instance.

#### Base Command

`aws-ec2-instance-metadata-options-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. | Required |
| instance_id | The ID of the instance. | Required |
| http_tokens | Indicates whether IMDSv2 is required. Possible values are: optional, required. | Optional |
| http_endpoint | Enables or disables the HTTP metadata endpoint on your instances. Possible values are: disabled, enabled. | Optional |

#### Context Output

There is no context output for this command.

### aws-iam-account-password-policy-update

***
Create/update password policy.

#### Base Command

`aws-iam-account-password-policy-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| minimum_password_length | The minimum number of characters allowed in an IAM user password. Possible values are: . | Optional |
| require_symbols | Specifies whether IAM user passwords must contain at least one of the non-alphanumeric characters. Can be "True" or "False". Possible values are: true, false. | Optional |
| require_numbers | Specifies whether IAM user passwords must contain at least one numeric character (0 to 9). Can be "True" or "False". Possible values are: true, false. | Optional |
| require_uppercase_characters | Specifies whether IAM user passwords must contain at least one uppercase character from the ISO basic Latin alphabet (A to Z). Can be "True" or "False". Possible values are: true, false. | Optional |
| require_lowercase_characters | Specifies whether IAM user passwords must contain at least one lowercase character from the ISO basic Latin alphabet (a to z). Can be "True" or "False". Possible values are: true, false. | Optional |
| allow_users_to_change_password | Allows all IAM users in your account to use the AWS Management Console to change their own passwords. Can be "True" or "False". Possible values are: true, false. | Optional |
| max_password_age | The number of days that an IAM user password is valid. Possible values are: . | Optional |
| password_reuse_prevention | Specifies the number of previous passwords that IAM users are prevented from reusing. Possible values are: . | Optional |
| hard_expiry | Prevents IAM users from setting a new password after their password has expired. Can be "True" or "False". Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-security-group-ingress-revoke

***
Revokes one or more ingress rules in a security group.

#### Base Command

`aws-ec2-security-group-ingress-revoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| group_id | The ID of the security group. | Required |
| protocol | The IP protocol: tcp, udp, icmp, or icmpv6. Use -1 to specify all protocols. When used with port and cidr arguments for simple rule revocation. | Optional |
| port | For TCP or UDP: The range of ports to revoke (e.g., "80" or "80-443"). For ICMP: A single integer or range (type-code) representing the ICMP type and code. Use with protocol and cidr for simple rule revocation. | Optional |
| cidr | The IPv4 address range in CIDR format (e.g., "0.0.0.0/0"). Use with protocol and port for simple rule revocation. | Optional |
| ip_permissions | The sets of IP permissions to revoke, in JSON format. Use this for complex rule configurations or when revoking multiple rules. Cannot be used together with protocol/port/cidr arguments. | Optional |

#### Context Output

There is no context output for this command.

### aws-iam-role-from-instance-profile-remove

***
Removes the specified IAM role from the specified EC2 instance profile.

#### Base Command

`aws-iam-role-from-instance-profile-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| instance_profile_name | The name of the instance profile to update. | Required |
| role_name | The name of the role to remove. | Required |

#### Context Output

There is no context output for this command.

### aws-eks-cluster-config-update

***
Updates an Amazon EKS cluster configuration. Only a single type of update can (logging / resources_vpc_config) is allowed per call.

#### Base Command

`aws-eks-cluster-config-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| cluster_name | The name of the Amazon EKS cluster to update. | Required |
| logging | Enable or disable exporting the Kubernetes control plane logs for your cluster to CloudWatch Logs . By default, cluster control plane logs aren’t exported to CloudWatch Logs . e.g. "{'clusterLogging': [{'types': ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'], 'enabled': true}]}". | Optional |
| resources_vpc_config | A JSON representation of the VPC configuration used by the cluster control plane. e.g. "{'subnetIds': ['string'], 'securityGroupIds': ['string'], 'endpointPublicAccess': True, 'endpointPrivateAccess': True, 'publicAccessCidrs': ['string']}". | Optional |

#### Context Output

There is no context output for this command.

### aws-rds-db-instance-modify

***
Modifies an Amazon RDS DB instance. Allows to change various settings of an existing DB instance, such as instance class, storage capacity, security groups, and other configuration parameters.

#### Base Command

`aws-rds-db-instance-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| db_instance_identifier | The identifier of DB instance to modify. This value is stored as a lowercase string. | Required |
| publicly_accessible | Specifies whether the DB instance is publicly accessible. Possible values are: true, false. | Optional |
| apply_immediately | Specifies whether the modifications in this request and any pending modifications are asynchronously applied as soon as possible, regardless of the PreferredMaintenanceWindow setting for the DB instance. By default, this parameter is disabled. If this parameter is disabled, changes to the DB instance are applied during the next maintenance window. Some parameter changes can cause an outage and are applied on the next call to RebootDBInstance , or the next failure reboot. Possible values are: true, false. | Optional |
| copy_tags_to_snapshot | Specifies whether to copy all tags from the DB instance to snapshots of the DB instance. By default, tags aren’t copied. Possible values are: true, false. | Optional |
| backup_retention_period | The number of days to retain automated backups. Setting this parameter to a positive number enables backups. Setting this parameter to 0 disables automated backups. | Optional |
| enable_iam_database_authentication | Specifies whether to enable mapping of Amazon Web Services Identity and Access Management (IAM) accounts to database accounts. By default, mapping isn’t enabled. Possible values are: true, false. | Optional |
| deletion_protection | Specifies whether the DB instance has deletion protection enabled. The database can’t be deleted when deletion protection is enabled. By default, deletion protection isn’t enabled. For more information, see Deleting a DB Instance. Possible values are: true, false. | Optional |
| auto_minor_version_upgrade | Specifies whether minor version upgrades are applied automatically to the DB instance during the maintenance window. An outage occurs when all the following conditions are met: The automatic upgrade is enabled for the maintenance window. A newer minor version is available. RDS has enabled automatic patching for the engine version. If any of the preceding conditions isn’t met, Amazon RDS applies the change as soon as possible and doesn’t cause an outage. For an RDS Custom DB instance, don’t enable this setting. Otherwise, the operation returns an error. Possible values are: true, false. | Optional |
| multi_az | Specifies whether the DB instance is a Multi-AZ deployment. Changing this parameter doesn’t result in an outage. The change is applied during the next maintenance window unless the ApplyImmediately parameter is enabled for this request. This setting doesn’t apply to RDS Custom DB instances. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

### aws-cloudtrail-trail-update

***
Updates trail settings that control what events you are logging, and how to handle log files. Changes to a trail do not require stopping the CloudTrail service. Use this action to designate an existing bucket for log delivery. If the existing bucket has previously been a target for CloudTrail log files, an IAM policy exists for the bucket. UpdateTrail must be called from the Region in which the trail was created; otherwise, an InvalidHomeRegionException is thrown.

#### Base Command

`aws-cloudtrail-trail-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| name | Specifies the name of the trail or trail ARN. | Required |
| s3_bucket_name | Specifies the name of the Amazon S3 bucket designated for publishing log files. | Optional |
| s3_key_prefix | Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery. | Optional |
| sns_topic_name | Specifies the name of the Amazon SNS topic defined for notification of log file delivery. | Optional |
| include_global_service_events | Specifies whether the trail is publishing events from global services such as IAM to the log files. Possible values are: true, false. | Optional |
| is_multi_region_trail | Specifies whether the trail applies only to the current region or to all regions. The default is false. If the trail exists only in the current region and this value is set to true, shadow trails (replications of the trail) will be created in the other regions. If the trail exists in all regions and this value is set to false, the trail will remain in the region where it was created, and its shadow trails in other regions will be deleted. Possible values are: true, false. | Optional |
| enable_log_file_validation | Specifies whether log file validation is enabled. The default is false. Possible values are: true, false. | Optional |
| cloud_watch_logs_log_group_arn | Specifies a log group name using an Amazon Resource Name (ARN), a unique identifier that represents the log group to which CloudTrail logs will be delivered. Not required unless you specify CloudWatchLogsRoleArn. | Optional |
| cloud_watch_logs_role_arn | Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group. | Optional |
| kms_key_id | Specifies the KMS key ID to use to encrypt the logs delivered by CloudTrail. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.CloudTrail.Trail.TrailARN | string | The Amazon Resource Name \(ARN\) of the trail. |
| AWS.CloudTrail.Trail.Name | string | The name of the trail. |
| AWS.CloudTrail.Trail.S3BucketName | string | The name of the Amazon S3 bucket into which CloudTrail delivers your trail files. |
| AWS.CloudTrail.Trail.S3KeyPrefix | string | The Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery. |
| AWS.CloudTrail.Trail.SnsTopicName | string | The name of the Amazon SNS topic defined for notification of log file delivery. |
| AWS.CloudTrail.Trail.SnsTopicARN | string | The Amazon Resource Name \(ARN\) of the Amazon SNS topic defined for notification of log file delivery. |
| AWS.CloudTrail.Trail.IncludeGlobalServiceEvents | boolean | Set to True to include AWS API calls from AWS global services such as IAM. |
| AWS.CloudTrail.Trail.IsMultiRegionTrail | boolean | Specifies whether the trail exists only in one region or exists in all regions. |
| AWS.CloudTrail.Trail.HomeRegion | string | The region in which the trail was created. |
| AWS.CloudTrail.Trail.LogFileValidationEnabled | boolean | Specifies whether log file validation is enabled. |
| AWS.CloudTrail.Trail.CloudWatchLogsLogGroupArn | string | Specifies an Amazon Resource Name \(ARN\), a unique identifier that represents the log group to which CloudTrail logs will be delivered. |
| AWS.CloudTrail.Trail.CloudWatchLogsRoleArn | string | Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group. |
| AWS.CloudTrail.Trail.KMSKeyId | string | Specifies the KMS key ID that encrypts the logs delivered by CloudTrail. |
| AWS.CloudTrail.Trail.HasCustomEventSelectors | boolean | Specifies if the trail has custom event selectors. |
| AWS.CloudTrail.Trail.HasInsightSelectors | boolean | Specifies whether a trail has insight selectors enabled. |
| AWS.CloudTrail.Trail.IsOrganizationTrail | boolean | Specifies whether the trail is an organization trail. |

### aws-ec2-security-group-ingress-authorize

***
Adds the specified inbound (ingress) rules to a security group.

#### Base Command

`aws-ec2-security-group-ingress-authorize`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| group_id | The ID of the security group. | Required |
| protocol | The IP protocol: tcp, udp, icmp, or icmpv6. Use -1 to specify all protocols. When used with port and cidr arguments for simple rule authorization. | Optional |
| port | For TCP or UDP: The range of ports to authorize (e.g., "80" or "80-443"). For ICMP: A single integer or range (type-code) representing the ICMP type and code. Use with protocol and cidr for simple rule authorization. | Optional |
| cidr | The IPv4 address range in CIDR format (e.g., "0.0.0.0/0"). Use with protocol and port for simple rule authorization. | Optional |
| ip_permissions | The sets of IP permissions to authorize, in JSON format. Use this for complex rule configurations or when authorizing multiple rules. Cannot be used together with protocol/port/cidr arguments. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-image-attribute-modify

***
Modifies the specified attribute of the specified AMI.

#### Base Command

`aws-ec2-image-attribute-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| image_id | The ID of the AMI. | Required |
| attribute | The AMI attribute to modify. Possible values are: description, launchPermission. | Required |
| operation_type | The operation to perform on the attribute. Possible values are: add, remove. | Optional |
| user_ids | The AWS account IDs to add to or remove from the list of users that have launch permissions for the AMI. | Optional |
| user_groups | The user groups to add to or remove from the list of user groups that have launch permissions for the AMI. | Optional |
| description | A new description for the AMI. | Optional |

#### Context Output

There is no context output for this command.

### aws-rds-db-cluster-snapshot-attribute-modify

***
Modifies the attributes associated with a DB cluster snapshot.

#### Base Command

`aws-rds-db-cluster-snapshot-attribute-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| db_cluster_snapshot_identifier | The identifier for the DB cluster snapshot to modify the attributes for. | Required |
| attribute_name | The name of the DB cluster snapshot attribute to modify. | Required |
| values_to_remove | A CSV list of DB cluster snapshot attributes to remove from the attribute specified by AttributeName. Default Value all. | Optional |
| values_to_add | A CSV list of DB cluster snapshot attributes to add to the attribute specified by AttributeName. | Optional |

#### Context Output

There is no context output for this command.

### aws-s3-bucket-logging-put

***
Configure logging settings for an AWS S3 bucket, allowing to monitor access to the bucket through detailed access logs that are delivered to a designated target bucket.

#### Base Command

`aws-s3-bucket-logging-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| bucket | The name of the bucket for which to set the logging parameters. | Required |
| target_bucket | The name of the bucket where server access logs should be delivered. If this is NOT provided, logging will be disabled. | Optional |
| target_prefix | The prefix to be used for log object keys (e.g., "logs/"). Objects will be stored as: targetBucket/targetPrefix/sourceBucket/YYYY-MM-DD-HH-MM-SS-UniqueString. | Optional |

#### Context Output

There is no context output for this command.

### aws-iam-login-profile-delete

***
Deletes the password for the specified IAM user, which terminates the user's ability to access AWS services through the AWS Management Console.

#### Base Command

`aws-iam-login-profile-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| user_name | The name of the user whose password you want to delete. | Required |

#### Context Output

There is no context output for this command.

### aws-rds-db-snapshot-attribute-modify

***
Adds or removes permission for the specified AWS account ID to restore the specified DB snapshot.

#### Base Command

`aws-rds-db-snapshot-attribute-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| db_snapshot_identifier | The identifier for the DB snapshot to modify the attributes for. | Required |
| attribute_name | The name of the DB snapshot attribute to modify. | Required |
| values_to_add | A list of DB snapshot attributes to add to the attribute specified by AttributeName. | Optional |
| values_to_remove | A list of DB snapshot attributes to remove from the attribute specified by AttributeName. | Optional |

#### Context Output

There is no context output for this command.

### aws-s3-bucket-policy-put

***
Applies an Amazon S3 bucket policy to an Outposts bucket.

#### Base Command

`aws-s3-bucket-policy-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| bucket | The name of the bucket to which the policy will be applied. | Required |
| policy | The bucket policy to apply as a JSON string. | Required |

#### Context Output

There is no context output for this command.

### aws-cloudtrail-logging-start

***
Starts the recording of AWS API calls and log file delivery for a trail. For a trail that is enabled in all regions, this operation must be called from the region in which the trail was created. This operation cannot be called on the shadow trails (replicated trails in other regions) of a trail that is enabled in all regions.

#### Base Command

`aws-cloudtrail-logging-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| name | Specifies the name or the CloudTrail ARN of the trail for which CloudTrail logs Amazon Web Services API calls. e.g. arn:aws:cloudtrail:us-east-2:123456789012:trail/MyTrail. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-instance-attribute-modify

***
Modifies the specified attribute of the specified instance. You can specify only one attribute at a time.

#### Base Command

`aws-ec2-instance-attribute-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| instance_id | The ID of the instance. | Required |
| disable_api_stop | Indicates whether an instance is enabled for stop protection. Possible values are: true, false. | Optional |
| groups | A comma-separated list of security groups to replace the instance's current security groups. You must specify the ID of at least one security group, even if it’s just the default security group for the VPC. | Optional |
| attribute | The name of the attribute to modify. Possible values: sourceDestCheck, groupSet, ebsOptimized, sriovNetSupport, enaSupport, enclaveOptions, disableApiStop. Possible values are: instanceType, kernel, ramdisk, userData, disableApiTermination, instanceInitiatedShutdownBehavior, rootDeviceName, blockDeviceMapping, productCodes, sourceDestCheck, groupSet, ebsOptimized, striovNetSupport, enaSupport, enclaveOptions, disableApiStop. | Optional |
| value | A new value for the attribute. Use only with the kernel, ramdisk, userData, disableApiTermination, or instanceInitiatedShutdownBehavior attribute. | Optional |

#### Context Output

There is no context output for this command.

### aws-iam-access-key-update

***
Changes the status of the specified access key from Active to Inactive, or vice versa. This operation can be used to disable a user's access key as part of a key rotation workflow.

#### Base Command

`aws-iam-access-key-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| access_key_id | The access key ID of the secret access key you want to update. | Required |
| status | The status you want to assign to the secret access key. Possible values are: Active, Inactive. | Required |
| user_name | The name of the user whose key you want to update. If you do not specify a user name, IAM determines the user name implicitly based on the AWS access key ID signing the request. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-security-group-egress-revoke

***
Removes the specified outbound (egress) rules from the specified security group.

#### Base Command

`aws-ec2-security-group-egress-revoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| group_id | The ID of the security group. | Required |
| protocol | The IP protocol: tcp, udp, icmp, or icmpv6. Use -1 to specify all protocols. When used with port and cidr arguments for simple rule revocation. | Optional |
| port | For TCP or UDP: The range of ports to revoke (e.g., "80" or "80-443"). For ICMP: A single integer or range (type-code) representing the ICMP type and code. Use with protocol and cidr for simple rule revocation. | Optional |
| cidr | The IPv4 address range in CIDR format (e.g., "0.0.0.0/0"). Use with protocol and port for simple rule revocation. | Optional |
| ip_permissions | The sets of IP permissions to revoke, in JSON format. Use this for complex rule configurations or when revoking multiple rules. Cannot be used together with protocol/port/cidr arguments. | Optional |

#### Context Output

There is no context output for this command.

### aws-iam-role-policy-put

***
Adds or updates an inline policy document that is embedded in the specified IAM role.

#### Base Command

`aws-iam-role-policy-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| role_name | The name of the role to associate the policy with. This parameter allows (through its regex pattern ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-. | Required |
| policy_name | The name of the policy document. This parameter allows (through its regex pattern ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-. | Required |
| policy_document | The policy document in JSON format. Must be a valid IAM policy document that defines the permissions for the role. | Required |

#### Context Output

There is no context output for this command.

### aws-rds-db-cluster-modify

***
Modifies settings for an Amazon RDS DB cluster. Allows you to update cluster settings such as port, master credentials, VPC security groups, deletion protection, and other configuration options.

#### Base Command

`aws-rds-db-cluster-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| db_cluster_identifier | The DB cluster identifier for the cluster being modified. This parameter isn’t case-sensitive. Valid for Cluster Type: Aurora DB clusters and Multi-AZ DB clusters Constraints: Must match the identifier of an existing DB cluster. | Required |
| deletion_protection | Specifies whether the DB cluster has deletion protection enabled. The database can’t be deleted when deletion protection is enabled. By default, deletion protection isn’t enabled. Possible values are: true, false. | Optional |
| enable_iam_database_authentication | Specifies whether to enable mapping of Amazon Web Services Identity and Access Management (IAM) accounts to database accounts. By default, mapping isn’t enabled. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

### aws-s3-public-access-block-update

***
Create or Modify the PublicAccessBlock configuration for an Amazon S3 bucket.

#### Base Command

`aws-s3-public-access-block-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| bucket | The name of the Amazon S3 bucket. | Required |
| block_public_acls | Specifies whether Amazon S3 should block public access control lists (ACLs) for this bucket and objects in this bucket. Possible values are: true, false. | Optional |
| ignore_public_acls | Specifies whether Amazon S3 should ignore public ACLs for this bucket and objects in this bucket. Possible values are: true, false. | Optional |
| block_public_policy | Specifies whether Amazon S3 should block public bucket policies for this bucket. Possible values are: true, false. | Optional |
| restrict_public_buckets | Specifies whether Amazon S3 should restrict public bucket policies for this bucket. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

### aws-iam-user-policy-put

***
Adds or updates an inline policy document that is embedded in the specified IAM user.

#### Base Command

`aws-iam-user-policy-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| user_name | The name of the user to associate the policy with. | Required |
| policy_name | The name of the policy document. | Required |
| policy_document | The policy document in JSON format. Must be a valid IAM policy document that defines the permissions for the user. | Required |

#### Context Output

There is no context output for this command.

### aws-s3-bucket-versioning-put

***
Sets the versioning state of an existing bucket.

#### Base Command

`aws-s3-bucket-versioning-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| bucket | The name of the bucket for which to set the logging parameters. | Required |
| mfa_delete | Specifies whether MFA delete is enabled in the bucket versioning configuration. This element is only returned if the bucket has been configured with MFA delete. If the bucket has never been so configured, this element is not returned. | Optional |
| status | The versioning state of the bucket. Possible values are: Enabled, Suspended. | Required |

#### Context Output

There is no context output for this command.

### aws-s3-bucket-acl-put

***
Sets the access control list (ACL) permissions for an existing Amazon S3 bucket. This command allows you to define who can access the bucket and what actions they can perform, using predefined ACLs. Since 2023, all new S3 buckets *block* ACLs by default for better security.

#### Base Command

`aws-s3-bucket-acl-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| acl | The canned ACL to apply to the bucket. Possible values are: private, public-read, public-read-write, authenticated-read. | Required |
| bucket | The bucket to which to apply the ACL. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-snapshot-attribute-modify

***
Adds or removes permission settings for the specified snapshot. Note: snapshots encrypted with the AWS-managed default key (alias/aws/ebs) cannot be shared—use unencrypted snapshots or those encrypted with a customer-managed KMS key to allow permission modifications.

#### Base Command

`aws-ec2-snapshot-attribute-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| snapshot_id | The ID of the snapshot. | Required |
| attribute | The snapshot attribute to modify. Default is createVolumePermission. | Required |
| operation_type | The operation to perform. Possible values are: add, remove. | Required |
| user_ids | A comma-separated list of AWS user account IDs to add to or remove from the list of users permitted to create EBS volumes from the snapshot. | Optional |
| group | The groups to add to or remove from the list of entities that have permission to create volumes from the snapshot. Possible values are: all. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-instances-describe

***
Describes specified instances or all instances.

#### Base Command

`aws-ec2-instances-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region to query instances from. Must be a valid AWS region identifier. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| instance_ids | A comma-separated list of instance IDs to describe. If empty, returns all accessible instances in the specified region. | Optional |
| filters | One or more custom filters to apply separated by ';' (e.g., name=&lt;name&gt;,values=&lt;values&gt;).You can specify up to 50 filters and up to 200 values per filter in a single request. | Optional |
| next_token | Token for pagination when retrieving large result sets. Use the InstancesNextToken value from a previous response to continue listing instances. | Optional |
| limit | Maximum number of instances to return in a single request. You cannot specify this parameter and the instance IDs parameter in the same request. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Instances.InstanceId | string | The ID of the instance. |
| AWS.EC2.Instances.ImageId | string | The ID of the AMI used to launch the instance. |
| AWS.EC2.Instances.State.Code | number | The current state of the instance as a 16-bit unsigned integer. |
| AWS.EC2.Instances.State.Name | string | The current state of the instance. |
| AWS.EC2.Instances.PrivateDnsName | string | The private DNS hostname name assigned to the instance. |
| AWS.EC2.Instances.PrivateIpAddress | string | The private IPv4 address assigned to the instance. |
| AWS.EC2.Instances.PublicDnsName | string | The public DNS name assigned to the instance. |
| AWS.EC2.Instances.PublicIpAddress | string | The public IPv4 address assigned to the instance. |
| AWS.EC2.Instances.InstanceType | string | The instance type. |
| AWS.EC2.Instances.KeyName | string | The name of the key pair used when the instance was launched. |
| AWS.EC2.Instances.LaunchTime | date | The time the instance was launched. |
| AWS.EC2.Instances.Placement.AvailabilityZone | string | The availability zone of the instance. |
| AWS.EC2.Instances.Placement.GroupName | string | The name of the placement group the instance is in. |
| AWS.EC2.Instances.Placement.Tenancy | string | The tenancy of the instance. |
| AWS.EC2.Instances.Platform | string | The platform the instance uses. The value is Windows for Windows instances; otherwise, blank. |
| AWS.EC2.Instances.Monitoring.State | string | Indicates whether detailed monitoring is enabled. |
| AWS.EC2.Instances.SubnetId | string | The ID of the subnet in which the instance is running. |
| AWS.EC2.Instances.VpcId | string | The ID of the VPC in which the instance is running. |
| AWS.EC2.Instances.Architecture | string | The architecture of the image. |
| AWS.EC2.Instances.SecurityGroups.GroupName | string | The name of the security group. |
| AWS.EC2.Instances.SecurityGroups.GroupId | string | The ID of the security group. |
| AWS.EC2.Instances.Tags.Key | string | The key of the tag. |
| AWS.EC2.Instances.Tags.Value | string | The value of the tag. |
| AWS.EC2.InstancesNextToken | string | Token to use for pagination in subsequent requests. |

### aws-ec2-instances-start

***
Starts an Amazon EBS-backed instance that was previously stopped.

#### Base Command

`aws-ec2-instances-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region where target instances are located. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| instance_ids | A comma-separated list of instance IDs to start, in i-xxxxxxxxx format. Must be in 'stopped' state and user must have permissions. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-instances-stop

***
Stops an Amazon EBS-backed instance.

#### Base Command

`aws-ec2-instances-stop`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region where target instances are located. Must be a valid AWS region identifier. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| instance_ids | A comma-separated list of instance IDs to stop. Must be in 'running' or 'pending' state. User must have stop permissions for each instance. | Required |
| force | Force stop instances without graceful shutdown. Default: false. Use with caution, as it may cause data loss. Possible values are: True, False. | Optional |
| hibernate | Hibernates the instance if the instance was enabled for hibernation at launch. Default: false. If the instance cannot hibernate successfully, a normal shutdown occurs. Possible values are: True, False. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-instances-terminate

***
Shuts down specified instances. This operation is idempotent; you can terminate an instance multiple times without causing an error.

#### Base Command

`aws-ec2-instances-terminate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region where target instances are located. Must be a valid AWS region identifier. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| instance_ids | A comma-separated list of instance IDs to terminate. If you specify multiple instances and the request fails (for example, because of a single incorrect instance ID), none of the instances are terminated. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-instances-run

***
Launches a specified number of instances using an AMI you have access to. You can save time by creating a launch template containing your parameters and using the template instead of entering the parameters each time. An instance is ready for you to use when it is in the running state. You can check the state of your instance using aws-ec2-instances-describe.

#### Base Command

`aws-ec2-instances-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region where instances will be created. Must be a valid AWS region identifier. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| count | The number of instances to launch. Must be greater than 0. | Required |
| image_id | The ID of the AMI. An AMI ID is required to launch an instance and must be specified here or in a launch template. | Optional |
| instance_type | The instance type, for example: t2.large, t3.medium, m5.xlarge. | Optional |
| security_group_ids | A comma-separated list of security group IDs. Use this for VPC instances. If you don’t specify a security group ID, we use the default security group for the VPC. | Optional |
| security_groups_names | A comma-separated list of security group names. For a nondefault VPC, you must use security group IDs instead. | Optional |
| subnet_id | The ID of the subnet to launch the instance into. If you don't choose a subnet, we will use a default one from your default VPC. If you don't have a default VPC, you must specify a subnet ID yourself in the request. | Optional |
| user_data | The user data to make available to the instance. This value will be base64 encoded automatically. Do not base64 encode this value prior to performing the operation. | Optional |
| disable_api_termination | Indicates whether termination protection is enabled for the instance. The default is false, which means that you can terminate the instance using the Amazon EC2 console, command line tools, or API. Possible values are: True, False. | Optional |
| iam_instance_profile_arn | The Amazon Resource Name (ARN) of the instance profile. Both iam_instance_profile_arn and iam_instance_profile_name are required if you would like to associate an instance profile. | Optional |
| iam_instance_profile_name | The name of the instance profile. Both iam_instance_profile_arn and iam_instance_profile_name are required if you would like to associate an instance profile. | Optional |
| key_name | The name of the key pair. Warning - If you do not specify a key pair, you can't connect to the instance unless you choose an AMI that is configured to allow users another way to log in. | Optional |
| ebs_optimized | Indicates whether the instance is optimized for Amazon EBS I/O. Possible values are: True, False. | Optional |
| device_name | The device name (for example, /dev/sdh or xvdh). If the argument is given, EBS arguments must also be specified. | Optional |
| ebs_volume_size | The size of the volume, in GiBs. You must specify either an ebs_snapshot_id or an ebs_volume_size. If you specify a snapshot, the default is the snapshot size. You can specify a volume size that is equal to or larger than the snapshot size. | Optional |
| ebs_volume_type | The volume type. Possible values are: gp2, gp3, io1, io2, st1, sc1, standard. | Optional |
| ebs_iops | The number of I/O operations per second (IOPS). For gp3, io1, and io2 volumes, this represents the number of IOPS that are provisioned for the volume. For gp2 volumes, this represents the baseline performance of the volume and the rate at which the volume accumulates I/O credits for bursting. This parameter is required for io1 and io2 volumes. The default for gp3 volumes is 3,000 IOPS. | Optional |
| ebs_delete_on_termination | Indicates whether the EBS volume is deleted on instance termination. Possible values are: True, False. | Optional |
| ebs_kms_key_id | Identifier (key ID, key alias, ID ARN, or alias ARN) for a user-managed CMK under which the EBS volume is encrypted. | Optional |
| ebs_snapshot_id | The ID of the snapshot. | Optional |
| ebs_encrypted | Indicates whether the encryption state of an EBS volume is changed while being restored from a backing snapshot. Possible values are: true, false. | Optional |
| launch_template_id | The ID of the launch template to use to launch the instances. Any parameters that you specify in the command override the same parameters in the launch template. You can specify either the name or ID of a launch template, but not both. | Optional |
| launch_template_name | The name of the launch template to use to launch the instances. Any parameters that you specify in the command override the same parameters in the launch template. You can specify either the name or ID of a launch template, but not both. | Optional |
| launch_template_version | The launch template version number, $Latest, or $Default. | Optional |
| tags | One or more tags to apply to a resource when the resource is being created. separated by ';' (e.g., key=&lt;name&gt;,value=&lt;value&gt;). | Optional |
| host_id | The dedicated Host ID. | Optional |
| enabled_monitoring | Indicates whether detailed monitoring is enabled. Otherwise, basic monitoring is enabled. Possible values are: True, False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Instances.InstanceId | string | The ID of the newly created instance. |
| AWS.EC2.Instances.ImageId | string | The ID of the AMI used to launch the instance. |
| AWS.EC2.Instances.State.Code | number | The current state of the instance as a 16-bit unsigned integer. |
| AWS.EC2.Instances.State.Name | string | The current state of the instance. |
| AWS.EC2.Instances.PrivateDnsName | string | The private DNS hostname name assigned to the instance. |
| AWS.EC2.Instances.PrivateIpAddress | string | The private IPv4 address assigned to the instance. |
| AWS.EC2.Instances.PublicDnsName | string | The public DNS name assigned to the instance. |
| AWS.EC2.Instances.PublicIpAddress | string | The public IPv4 address assigned to the instance. |
| AWS.EC2.Instances.InstanceType | string | The instance type. |
| AWS.EC2.Instances.KeyName | string | The name of the key pair used when the instance was launched. |
| AWS.EC2.Instances.LaunchTime | date | The time the instance was launched. |
| AWS.EC2.Instances.Placement.AvailabilityZone | string | The availability zone of the instance. |
| AWS.EC2.Instances.Placement.GroupName | string | The name of the placement group the instance is in. |
| AWS.EC2.Instances.Placement.Tenancy | string | The tenancy of the instance. |
| AWS.EC2.Instances.Platform | string | The platform the instance uses. The value is Windows for Windows instances; otherwise, blank. |
| AWS.EC2.Instances.Monitoring.State | string | Indicates whether detailed monitoring is enabled. |
| AWS.EC2.Instances.SubnetId | string | The ID of the subnet in which the instance is running. |
| AWS.EC2.Instances.VpcId | string | The ID of the VPC in which the instance is running. |
| AWS.EC2.Instances.Architecture | string | The architecture of the image. |
| AWS.EC2.Instances.BlockDeviceMappings.DeviceName | string | The device name. |
| AWS.EC2.Instances.BlockDeviceMappings.Ebs | Dictionary | Parameters used to automatically set up EBS volumes when the instance is launched. |
| AWS.EC2.Instances.SecurityGroups.GroupName | string | The name of the security group. |
| AWS.EC2.Instances.SecurityGroups.GroupId | string | The ID of the security group. |
| AWS.EC2.Instances.IamInstanceProfile.Arn | string | The Amazon Resource Name \(ARN\) of the instance profile. |
| AWS.EC2.Instances.IamInstanceProfile.Id | string | The ID of the instance profile. |
| AWS.EC2.Instances.Tags.Key | string | The key of the tag. |
| AWS.EC2.Instances.Tags.Value | string | The value of the tag. |
| AWS.EC2.Instances.EbsOptimized | boolean | Indicates whether the instance is optimized for Amazon EBS I/O. |
| AWS.EC2.Instances.NetworkInterfaces.NetworkInterfaceId | string | The ID of the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.SubnetId | string | The ID of the subnet associated with the network interface. Applies only if creating a network interface when launching an instance. |
| AWS.EC2.Instances.NetworkInterfaces.VpcId | string | The ID of the VPC. |
| AWS.EC2.Instances.NetworkInterfaces.Description | string | The description of the network interface. Applies only if creating a network interface when launching an instance. |
| AWS.EC2.Instances.NetworkInterfaces.OwnerId | string | The ID of the AWS account that owns the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.Status | string | The status of the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.MacAddress | string | The MAC address. |
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddress | string | The IPv4 address of the network interface within the subnet. |
| AWS.EC2.Instances.NetworkInterfaces.PrivateDnsName | string | The private DNS name. |
| AWS.EC2.Instances.NetworkInterfaces.SourceDestCheck | boolean | Indicates whether to validate network traffic to or from this network interface. |
| AWS.EC2.ReservationId | string | The ID of the reservation. |
| AWS.EC2.OwnerId | string | The ID of the AWS account that owns the reservation. |
| AWS.EC2.ResponseMetadata.RequestId | string | The request ID for the run instances operation. |
| AWS.EC2.ResponseMetadata.HTTPStatusCode | number | The HTTP status code of the response. |
