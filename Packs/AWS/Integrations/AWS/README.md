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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| group_id | The ID of the security group. | Required |
| protocol | The IP protocol: tcp, udp, icmp, or icmpv6 or a number. Use -1 to specify all protocols. Use with port and CIDR arguments for simple rule revocation. | Optional |
| from_port | If the protocol is TCP or UDP, this is the start of the port range. If the protocol is ICMP or ICMPv6, this is the ICMP type or -1 (all ICMP types). | Optional |
| to_port | If the protocol is TCP or UDP, this is the end of the port range. If the protocol is ICMP or ICMPv6, this is the ICMP code or -1 (all ICMP codes). If the start port is -1 (all ICMP types), then the end port must be -1 (all ICMP codes). | Optional |
| cidr | The IPv4 address range in CIDR format (e.g., "0.0.0.0/0"). Use with protocol and port for simple rule revocation. | Optional |
| ip_permissions | The sets of IP permissions to revoke, in JSON format. Use this for complex rule configurations or when revoking multiple rules. Cannot be used together with protocol/port/CIDR arguments. | Optional |

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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| name | The name of the trail or trail ARN. | Required |
| s3_bucket_name | The name of the Amazon S3 bucket designated for publishing log files. | Optional |
| s3_key_prefix | The Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery. | Optional |
| sns_topic_name | The name of the Amazon SNS topic defined for notification of log file delivery. | Optional |
| include_global_service_events | Weather the trail is publishing events from global services such as IAM to the log files. Possible values are: true, false. | Optional |
| is_multi_region_trail | Weather the trail applies only to the current region or to all regions. The default is false. If the trail exists only in the current region and this value is set to true, shadow trails (replications of the trail) will be created in the other regions. If the trail exists in all regions and this value is set to false, the trail will remain in the region where it was created, and its shadow trails in other regions will be deleted. Possible values are: true, false. | Optional |
| enable_log_file_validation | Weather log file validation is enabled. The default is false. Possible values are: true, false. | Optional |
| cloud_watch_logs_log_group_arn | Specifies a log group name using an Amazon Resource Name (ARN), a unique identifier that represents the log group to which CloudTrail logs will be delivered. Not required unless you specify CloudWatchLogsRoleArn. | Optional |
| cloud_watch_logs_role_arn | The role for the CloudWatch Logs endpoint to assume to write to a user's log group. | Optional |
| kms_key_id | The KMS key ID to use to encrypt the logs delivered by CloudTrail. | Optional |

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
| AWS.CloudTrail.Trail.IsMultiRegionTrail | boolean | Weather the trail exists only in one region or exists in all regions. |
| AWS.CloudTrail.Trail.HomeRegion | string | The region in which the trail was created. |
| AWS.CloudTrail.Trail.LogFileValidationEnabled | boolean | Weather log file validation is enabled. |
| AWS.CloudTrail.Trail.CloudWatchLogsLogGroupArn | string | Amazon Resource Name \(ARN\), a unique identifier that represents the log group to which CloudTrail logs will be delivered. |
| AWS.CloudTrail.Trail.CloudWatchLogsRoleArn | string | The role for the CloudWatch Logs endpoint to assume to write to a user's log group. |
| AWS.CloudTrail.Trail.KMSKeyId | string | The KMS key ID that encrypts the logs delivered by CloudTrail. |
| AWS.CloudTrail.Trail.HasCustomEventSelectors | boolean | Specifies if the trail has custom event selectors. |
| AWS.CloudTrail.Trail.HasInsightSelectors | boolean | Weather a trail has insight selectors enabled. |
| AWS.CloudTrail.Trail.IsOrganizationTrail | boolean | Whether the trail is an organization trail. |

### aws-ec2-security-group-ingress-authorize

***
Adds the specified inbound (ingress) rules to a security group.

#### Base Command

`aws-ec2-security-group-ingress-authorize`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| group_id | The ID of the security group. | Required |
| protocol | The IP protocol: tcp, udp, icmp, or icmpv6 or a number. Use -1 to specify all protocols. Use with port and CIDR arguments for simple rule authorization. | Optional |
| from_port | If the protocol is TCP or UDP, this is the start of the port range. If the protocol is ICMP or ICMPv6, this is the ICMP type or -1 (all ICMP types). | Optional |
| to_port | If the protocol is TCP or UDP, this is the end of the port range. If the protocol is ICMP or ICMPv6, this is the ICMP code or -1 (all ICMP codes). If the start port is -1 (all ICMP types), then the end port must be -1 (all ICMP codes). | Optional |
| cidr | The IPv4 address range in CIDR format (e.g., "0.0.0.0/0"). Use with protocol and port for simple rule authorization. | Optional |
| ip_permissions | The sets of IP permissions to authorize, in JSON format. Use this for complex rule configurations or when authorizing multiple rules. Cannot be used together with protocol/port/CIDR arguments. | Optional |

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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| db_cluster_snapshot_identifier | The identifier for the DB cluster snapshot to modify the attributes for. | Required |
| attribute_name | The name of the DB cluster snapshot attribute to modify. | Required |
| values_to_remove | A CSV list of DB cluster snapshot attributes to remove from the attribute specified by AttributeName. Default Value all. | Optional |
| values_to_add | A CSV list of DB cluster snapshot attributes to add to the attribute specified by AttributeName. | Optional |

#### Context Output

There is no context output for this command.

### aws-s3-bucket-logging-put

***
Configures logging settings for an AWS S3 bucket, enabling monitoring of bucket access through detailed logs delivered to a designated target bucket.

#### Base Command

`aws-s3-bucket-logging-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| bucket | The name of the bucket to which the policy will be applied. | Required |
| policy | The bucket policy to apply as a JSON string. | Required |

#### Context Output

There is no context output for this command.

### aws-cloudtrail-logging-start

***
Starts recording AWS API calls and log file delivery for a trail. For a trail enabled in all regions, this operation must be called from the region where the trail was created. This operation cannot be called on shadow trails (replicated trails in other regions) of a trail that is enabled in all regions.

#### Base Command

`aws-cloudtrail-logging-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| name | The name or the CloudTrail ARN of the trail for which CloudTrail logs Amazon Web Services API calls. e.g. arn:aws:cloudtrail:us-east-2:123456789012:trail/MyTrail. | Required |

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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| group_id | The ID of the security group. | Required |
| protocol | The IP protocol: tcp, udp, icmp, or icmpv6 or a number. Use -1 to specify all protocols. Use with port and CIDR arguments for simple rule revocation. | Optional |
| from_port | If the protocol is TCP or UDP, this is the start of the port range. If the protocol is ICMP or ICMPv6, this is the ICMP type or -1 (all ICMP types). | Optional |
| to_port | If the protocol is TCP or UDP, this is the end of the port range. If the protocol is ICMP or ICMPv6, this is the ICMP code or -1 (all ICMP codes). If the start port is -1 (all ICMP types), then the end port must be -1 (all ICMP codes). | Optional |
| cidr | The IPv4 address range in CIDR format (e.g., "0.0.0.0/0"). Use with protocol and port for simple rule revocation. | Optional |
| ip_permissions | The sets of IP permissions to revoke, in JSON format. Use this for complex rule configurations or when revoking multiple rules. Cannot be used together with protocol/port/CIDR arguments. | Optional |

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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| acl | The canned ACL to apply to the bucket. Possible values are: private, public-read, public-read-write, authenticated-read. | Required |
| bucket | The bucket to which to apply the ACL. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-snapshot-attribute-modify

***
Adds or removes permission settings for the specified snapshot. Note: snapshots encrypted with the AWS-managed default key (alias/aws/ebs) cannot be shared. Use unencrypted snapshots or those encrypted with a customer-managed KMS key to allow permission modifications.

#### Base Command

`aws-ec2-snapshot-attribute-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| snapshot_id | The ID of the snapshot. | Required |
| attribute | The snapshot attribute to modify. Default is createVolumePermission. | Required |
| operation_type | The operation to perform. Possible values are: add, remove. | Required |
| user_ids | A comma-separated list of AWS user account IDs to add to or remove from the list of users permitted to create EBS volumes from the snapshot. | Optional |
| group | The groups to add to or remove from the list of entities that have permission to create volumes from the snapshot. Possible values are: all. | Optional |

#### Context Output

There is no context output for this command.

### aws-s3-bucket-encryption-get

***
Retrieves the default encryption configuration for an Amazon S3 bucket. Shows the server-side encryption settings that are applied to new objects stored in the bucket.

#### Base Command

`aws-s3-bucket-encryption-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| bucket | Name of the S3 bucket to retrieve encryption configuration from. Must follow S3 naming conventions. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3-Buckets.BucketName | string | Name of the S3 bucket. |
| AWS.S3-Buckets.ServerSideEncryptionConfiguration.Rules | array | Container for information about a particular server-side encryption configuration rule. |

### aws-s3-file-download

***
Download a file from S3 bucket to the War Room.

#### Base Command

`aws-s3-file-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| bucket | Name of the target S3 bucket. Must follow S3 naming conventions. | Required |
| key | Key (path) of the file to download from the S3 bucket. | Required |
| region | AWS region where the S3 bucket is located. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. |
| File.SHA1 | String | The SHA1 hash of the file. |
| File.SHA256 | String | The SHA256 hash of the file. |
| File.Name | String | The name of the file. |
| File.SSDeep | String | The SSDeep hash of the file. |
| File.EntryID | String | The entry ID of the file. |
| File.Info | String | File information. |
| File.Type | String | The file type. |
| File.MD5 | String | The MD5 hash of the file. |
| File.Extension | String | The file extension. |

### aws-s3-bucket-policy-delete

***
Deletes the bucket policy from an Amazon S3 bucket. This operation removes all policy-based access controls from the bucket, potentially changing access permissions.

#### Base Command

`aws-s3-bucket-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| bucket | The name of the Amazon S3 bucket from which to delete the bucket policy, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

There is no context output for this command.

### aws-ecs-cluster-settings-update

***
Updates the containerInsights setting of an ECS cluster.

#### Base Command

`aws-ecs-cluster-settings-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| cluster_name | The name of the cluster. | Required |
| value | The value of the containerInsights setting to update. Possible values are: enabled, disabled, enhanced. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

There is no context output for this command.

### aws-s3-file-upload

***
Upload file to S3 bucket.

#### Base Command

`aws-s3-file-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| entryID | Entry ID of the file to upload. | Required |
| bucket | Name of the S3 bucket containing the file. Must follow S3 naming conventions. | Required |
| key | Key (path) where the file will be stored in the S3 bucket. | Required |
| region | AWS region where the S3 bucket is located. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-subnet-attribute-modify

***
Modifies a subnet attribute.

#### Base Command

`aws-ec2-subnet-attribute-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| subnet_id | The ID of the subnet. | Required |
| assign_ipv6_address_on_creation | Set to true to assign an IPv6 address to network interfaces created in the specified subnet. | Optional |
| customer_owned_ipv4_pool | The customer-owned IPv4 address pool associated with the subnet. | Optional |
| disable_lni_at_device_index | Set to true to disable local network interfaces at the current position. | Optional |
| enable_dns64 | Indicates whether DNS queries made to the Amazon-provided DNS Resolver in this subnet should return synthetic IPv6 addresses for IPv4-only destinations. | Optional |
| enable_lni_at_device_index | Indicates the device position for local network interfaces in this subnet. | Optional |
| enable_resource_name_dns_aaaa_record_on_launch | Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records. | Optional |
| enable_resource_name_dns_a_record_on_launch | Indicates whether to respond to DNS queries for instance hostnames with DNS A records. | Optional |
| map_customer_owned_ip_on_launch | Set to true to assign a customer-owned IPv4 address to network interfaces attached to instances created in the specified subnet. | Optional |
| map_public_ip_on_launch | Set to true to assign a public IPv4 address to network interfaces attached to instances created in the specified subnet. | Optional |
| private_dns_hostname_type_on_launch | The type of hostname to assign to instances in the subnet at launch. | Optional |

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
| region | The AWS region where target instances are located. Must be a valid AWS region identifier. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_ids | A comma-separated list of instance IDs to terminate. If you specify multiple instances and the request fails (for example, because of a single incorrect instance ID), none of the instances are terminated. | Required |

#### Context Output

There is no context output for this command.

### aws-s3-public-access-block-get

***
Retrieves the public access block configuration for an Amazon S3 bucket. Shows the current settings that control public access to the bucket and its objects.

#### Base Command

`aws-s3-public-access-block-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| bucket | The name of the Amazon S3 bucket to retrieve public access block configuration from. | Required |
| expected_bucket_owner | The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3-Buckets.BucketName | string | Name of the S3 bucket. |
| AWS.S3-Buckets.PublicAccessBlock.BlockPublicAcls | boolean | Whether Amazon S3 blocks public access control lists \(ACLs\) for this bucket and objects in this bucket. |
| AWS.S3-Buckets.PublicAccessBlock.IgnorePublicAcls | boolean | Whether Amazon S3 ignores public ACLs for this bucket and objects in this bucket. |
| AWS.S3-Buckets.PublicAccessBlock.BlockPublicPolicy | boolean | Whether Amazon S3 blocks public bucket policies for this bucket. |
| AWS.S3-Buckets.PublicAccessBlock.RestrictPublicBuckets | boolean | Whether Amazon S3 restricts public bucket policies for this bucket. |

### aws-ec2-instances-stop

***
Stops an Amazon EBS-backed instance.

#### Base Command

`aws-ec2-instances-stop`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region where target instances are located. Must be a valid AWS region identifier. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_ids | A comma-separated list of instance IDs to stop. Must be in 'running' or 'pending' state. User must have stop permissions for each instance. | Required |
| force | Force stop instances without graceful shutdown. Default: false. Use with caution, as it may cause data loss. Possible values are: true, false. Default is false. | Optional |
| hibernate | Hibernates the instance if the instance was enabled for hibernation at launch. If the instance cannot hibernate successfully, a normal shutdown occurs. Possible values are: true, false. Default is false. | Optional |

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
| region | The AWS region to query instances from. Must be a valid AWS region identifier. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_ids | A comma-separated list of instance IDs to describe. If empty, returns all accessible instances in the specified region. | Optional |
| filters | One or more custom filters to apply, separated by ';' (for example, name=&lt;name&gt;;values=&lt;values&gt;).You can specify up to 50 filters and up to 200 values per filter in a single request. | Optional |
| next_token | Token for pagination when retrieving large result sets. Use the InstancesNextToken value from a previous response to continue listing instances. | Optional |
| limit | Maximum number of instances to return in a single request. You cannot specify this parameter and the instance IDs parameter in the same request. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.InstancesNextToken | String | Token to use for pagination in subsequent requests. |
| AWS.EC2.Instances.Architecture | String | The architecture of the image. |
| AWS.EC2.Instances.BlockDeviceMappings.DeviceName | String | The device name. |
| AWS.EC2.Instances.BlockDeviceMappings.Ebs | Dictionary | Parameters used to automatically set up EBS volumes when the instance is launched. |
| AWS.EC2.Instances.ClientToken | String | The idempotency token you provided when you launched the instance, if applicable. |
| AWS.EC2.Instances.EbsOptimized | Boolean | Indicates whether the instance is optimized for Amazon EBS I/O. |
| AWS.EC2.Instances.EnaSupport | Boolean | Specifies whether enhanced networking with ENA is enabled. |
| AWS.EC2.Instances.Hypervisor | String | The hypervisor type of the instance. |
| AWS.EC2.Instances.IamInstanceProfile.Arn | String | The Amazon Resource Name \(ARN\) of the instance profile. |
| AWS.EC2.Instances.IamInstanceProfile.Id | String | The ID of the instance profile. |
| AWS.EC2.Instances.InstanceLifecycle | String | Indicates whether this is a Spot Instance or a Scheduled Instance. |
| AWS.EC2.Instances.NetworkInterfaces.Association | Dictionary | The association information for an Elastic IPv4 associated with the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.Attachment | Dictionary | The network interface attachment. |
| AWS.EC2.Instances.NetworkInterfaces.Description | String | The description of the network interface. Applies only if creating a network interface when launching an instance. |
| AWS.EC2.Instances.NetworkInterfaces.Groups | Dictionary | The security groups. |
| AWS.EC2.Instances.NetworkInterfaces.Ipv6Addresses | Dictionary | The IPv6 addresses associated with the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.MacAddress | String | The MAC address. |
| AWS.EC2.Instances.NetworkInterfaces.NetworkInterfaceId | String | The ID of the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.OwnerId | String | The ID of the AWS account that owns the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.PrivateDnsName | String | The private DNS name. |
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddress | String | The IPv4 address of the network interface within the subnet. |
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses | Array | The private IPv4 addresses associated with the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.SourceDestCheck | Boolean | Indicates whether to validate network traffic to or from this network interface. |
| AWS.EC2.Instances.NetworkInterfaces.Status | String | The status of the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.SubnetId | String | The ID of the subnet associated with the network interface. Applies only if creating a network interface when launching an instance. |
| AWS.EC2.Instances.NetworkInterfaces.VpcId | String | The ID of the VPC. |
| AWS.EC2.Instances.NetworkInterfaces.InterfaceType | String | The type of network interface. |
| AWS.EC2.Instances.NetworkInterfaces.Ipv4Prefixes | Array | The IPv4 prefixes assigned to the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.Ipv6Prefixes | Array | The IPv6 prefixes assigned to the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.ConnectionTrackingConfiguration | Dictionary | A security group connection tracking configuration that enables you to set the timeout for connection tracking on an Elastic network interface. |
| AWS.EC2.Instances.NetworkInterfaces.Operator | Dictionary | The service provider that manages the network interface. |
| AWS.EC2.Instances.OutpostArn | String | The Amazon Resource Name \(ARN\) of the Outpost. |
| AWS.EC2.Instances.RootDeviceName | String | The device name of the root device volume. |
| AWS.EC2.Instances.RootDeviceType | String | The root device type used by the AMI. |
| AWS.EC2.Instances.SecurityGroups.GroupId | String | The ID of the security group. |
| AWS.EC2.Instances.SecurityGroups.GroupName | String | The name of the security group. |
| AWS.EC2.Instances.SourceDestCheck | Boolean | Indicates whether source/destination checking is enabled. |
| AWS.EC2.Instances.SpotInstanceRequestId | String | The ID of the request for a Spot Instance request. |
| AWS.EC2.Instances.SriovNetSupport | String | Specifies whether enhanced networking with the Intel 82599 Virtual Function interface is enabled. |
| AWS.EC2.Instances.StateReason | Dictionary | The reason for the most recent state transition. May be an empty string. |
| AWS.EC2.Instances.Tags.Key | String | The key of the tag. |
| AWS.EC2.Instances.Tags.Value | String | The value of the tag. |
| AWS.EC2.Instances.VirtualizationType | String | The virtualization type of the instance. |
| AWS.EC2.Instances.CpuOptions | Dictionary | The CPU options for the instance. |
| AWS.EC2.Instances.CapacityBlockId | String | The ID of the Capacity Block. |
| AWS.EC2.Instances.CapacityReservationId | String | The ID of the Capacity Reservation. |
| AWS.EC2.Instances.CapacityReservationSpecification | Dictionary | Information about the Capacity Reservation targeting option. |
| AWS.EC2.Instances.HibernationOptions.Configured | Boolean | Indicates whether the instance is enabled for hibernation. |
| AWS.EC2.Instances.Licenses.LicenseConfigurationArn | String | The Amazon Resource Name \(ARN\) of the license configuration. |
| AWS.EC2.Instances.MetadataOptions | Dictionary | The metadata options for the instance. |
| AWS.EC2.Instances.EnclaveOptions.Enabled | Boolean | Indicates whether the instance is enabled for Amazon Web Services Nitro Enclaves. |
| AWS.EC2.Instances.BootMode | String | The boot mode that was specified by the AMI. |
| AWS.EC2.Instances.PlatformDetails | String | The platform details value for the instance. |
| AWS.EC2.Instances.UsageOperation | String | The usage operation value for the instance. |
| AWS.EC2.Instances.UsageOperationUpdateTime | Date | The time that the usage operation was last updated. |
| AWS.EC2.Instances.PrivateDnsNameOptions.HostnameType | String | The type of hostname to assign to an instance. |
| AWS.EC2.Instances.PrivateDnsNameOptions.EnableResourceNameDnsARecord | Boolean | Indicates whether to respond to DNS queries for instance hostnames with DNS A records. |
| AWS.EC2.Instances.PrivateDnsNameOptions.EnableResourceNameDnsAAAARecord | Boolean | Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records. |
| AWS.EC2.Instances.Ipv6Address | String | The IPv6 address assigned to the instance. |
| AWS.EC2.Instances.TpmSupport | String | If the instance is configured for NitroTPM support, the value is v2.0. |
| AWS.EC2.Instances.MaintenanceOptions.AutoRecovery | String | Information on the current automatic recovery behavior of your instance. |
| AWS.EC2.Instances.MaintenanceOptions.RebootMigration | String | Specifies whether to attempt reboot migration during a user-initiated reboot of an instance that has a scheduled system-reboot event. |
| AWS.EC2.Instances.CurrentInstanceBootMode | String | The boot mode that is used to boot the instance at launch or start. |
| AWS.EC2.Instances.NetworkPerformanceOptions.BandwidthWeighting | String | Contains settings for the network performance options for your instance. |
| AWS.EC2.Instances.Operator | Dictionary | The service provider that manages the instance. |
| AWS.EC2.Instances.InstanceId | String | The ID of the instance. |
| AWS.EC2.Instances.ImageId | String | The ID of the AMI used to launch the instance. |
| AWS.EC2.Instances.State.Code | Number | The current state of the instance as a 16-bit unsigned integer. |
| AWS.EC2.Instances.State.Name | String | The current state of the instance. |
| AWS.EC2.Instances.PrivateDnsName | String | The private DNS hostname name assigned to the instance. |
| AWS.EC2.Instances.PublicDnsName | String | The public DNS name assigned to the instance. |
| AWS.EC2.Instances.StateTransitionReason | String | The reason for the most recent state transition. May be an empty string. |
| AWS.EC2.Instances.KeyName | String | The name of the key pair used when the instance was launched. |
| AWS.EC2.Instances.AmiLaunchIndex | Number | The AMI launch index, which can be used to find this instance in the launch group. |
| AWS.EC2.Instances.ProductCodes | Dictionary | The product codes attached to this instance, if applicable. |
| AWS.EC2.Instances.InstanceType | String | The instance type. |
| AWS.EC2.Instances.LaunchTime | String | The time the instance was launched. |
| AWS.EC2.Instances.Placement.AvailabilityZoneId | String | The ID of the Availability Zone of the instance. |
| AWS.EC2.Instances.Placement.Affinity | String | The affinity setting for the instance on the Dedicated Host. |
| AWS.EC2.Instances.Placement.GroupName | String | The name of the placement group the instance is in. |
| AWS.EC2.Instances.Placement.PartitionNumber | Number | The number of the partition that the instance is in. |
| AWS.EC2.Instances.Placement.HostId | String | The ID of the Dedicated Host on which the instance resides. |
| AWS.EC2.Instances.Placement.Tenancy | String | The tenancy of the instance. |
| AWS.EC2.Instances.Placement.HostResourceGroupArn | String | The ARN of the host resource group in which to launch the instances. |
| AWS.EC2.Instances.Placement.GroupId | String | The ID of the placement group that the instance is in. |
| AWS.EC2.Instances.Placement.AvailabilityZone | String | The availability zone of the instance. |
| AWS.EC2.Instances.KernelId | String | The kernel associated with this instance, if applicable. |
| AWS.EC2.Instances.RamdiskId | String | The RAM disk associated with this instance, if applicable. |
| AWS.EC2.Instances.Platform | String | The platform the instance uses. The value is Windows for Windows instances; otherwise, blank. |
| AWS.EC2.Instances.Monitoring.State | String | Indicates whether detailed monitoring is enabled. |
| AWS.EC2.Instances.SubnetId | String | The ID of the subnet in which the instance is running. |
| AWS.EC2.Instances.VpcId | String | The ID of the VPC in which the instance is running. |
| AWS.EC2.Instances.PrivateIpAddress | String | The private IPv4 address assigned to the instance. |
| AWS.EC2.Instances.PublicIpAddress | String | The public IPv4 address assigned to the instance. |

### aws-s3-bucket-policy-get

***
Retrieves the bucket policy for an Amazon S3 bucket. Returns the policy document in JSON format if one exists.

#### Base Command

`aws-s3-bucket-policy-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| bucket | The name of the S3 bucket whose policy you want to retrieve. Must follow S3 naming conventions. | Required |
| expected_bucket_owner | The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3-Buckets.BucketName | string | Name of the S3 bucket. |
| AWS.S3-Buckets.Policy.Version | string | The version of the policy. |
| AWS.S3-Buckets.Policy.Id | string | The id of the policy. |
| AWS.S3-Buckets.Policy.Statement.Sid | string | Identifier of the policy statement. |
| AWS.S3-Buckets.Policy.Statement.Effect | string | Specifies whether the statement results in an allow or an explicit deny. |
| AWS.S3-Buckets.Policy.Statement.Principal | unknown | Specify the principal that is allowed or denied access to a resource. |
| AWS.S3-Buckets.Policy.Statement.Action | unknown | Describes the specific action or actions that will be allowed or denied. |
| AWS.S3-Buckets.Policy.Statement.Resource | unknown | Defines the object or objects that the statement applies to. |
| AWS.S3-Buckets.Policy.Statement.Condition | string | Specify conditions for when a policy is in effect. |

### aws-cloudtrail-trails-describe

***
Retrieves settings for the specified trail or returns information about all trails in the current AWS account.

#### Base Command

`aws-cloudtrail-trails-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| trail_names | A comma-separated list of trail names or trail ARNs. If the list is empty, it returns information for the trail in the current region. | Optional |
| include_shadow_trails | Include shadow trails in the response. A shadow trail is a replication in a region of a trail created in another region. Possible values are: true, false. Default is true. | Optional |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.CloudTrail.Trails.Name | string | The name of the trail, as set in CreateTrail. |
| AWS.CloudTrail.Trails.S3BucketName | string | The name of the Amazon S3 bucket where CloudTrail delivers trail files. |
| AWS.CloudTrail.Trails.S3KeyPrefix | string | The Amazon S3 key prefix appended to the bucket name designated for log file delivery. |
| AWS.CloudTrail.Trails.SnsTopicARN | string | The ARN of the Amazon SNS topic that CloudTrail uses to send notifications when log files are delivered. |
| AWS.CloudTrail.Trails.IncludeGlobalServiceEvents | boolean | Whether to include AWS API calls from AWS global services such as IAM. |
| AWS.CloudTrail.Trails.IsMultiRegionTrail | boolean | Specifies whether the trail belongs only to one region or exists in all regions. |
| AWS.CloudTrail.Trails.HomeRegion | string | The region where the trail was created. |
| AWS.CloudTrail.Trails.TrailARN | string | The ARN of the trail. |
| AWS.CloudTrail.Trails.LogFileValidationEnabled | boolean | Whether log file validation is enabled. |
| AWS.CloudTrail.Trails.CloudWatchLogsLogGroupArn | string | The ARN of the CloudWatch log group to which CloudTrail logs are delivered. |
| AWS.CloudTrail.Trails.CloudWatchLogsRoleArn | string | The role assumed by CloudTrail to write logs to the CloudWatch log group. |
| AWS.CloudTrail.KmsKeyId | string | The KMS key ID that encrypts logs delivered by CloudTrail. |
| AWS.CloudTrail.HasCustomEventSelectors | boolean | Specifies if the trail has custom event selectors. |
| AWS.CloudTrail.HasInsightSelectors | boolean | Specifies whether a trail has insight types specified in an InsightSelector list. |
| AWS.CloudTrail.IsOrganizationTrail | boolean | Specifies whether the trail is an organization trail. |

### aws-ec2-instances-start

***
Starts an Amazon EBS-backed instance that was previously stopped.

#### Base Command

`aws-ec2-instances-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region where target instances are located. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_ids | A comma-separated list of instance IDs to start, in i-xxxxxxxxx format. Must be in 'stopped' state and user must have permissions. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-snapshot-create

***
Creates a snapshot of an EBS volume and stores it in Amazon S3. You can use snapshots for backups, to make copies of EBS volumes, and to save data before shutting down an instance.

#### Base Command

`aws-ec2-snapshot-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| volume_id | The ID of the EBS volume. | Required |
| description | A description for the snapshot. | Optional |
| tags | The tags to apply to the snapshot during creation. | Optional |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Snapshot.DataEncryptionKeyId | string | The data encryption key identifier for the snapshot. |
| AWS.EC2.Snapshot.Description | string | The description for the snapshot. |
| AWS.EC2.Snapshot.Encrypted | number | Indicates whether the snapshot is encrypted. |
| AWS.EC2.Snapshot.KmsKeyId | string | The full ARN of the AWS Key Management Service \(AWS KMS\) customer master key \(CMK\) that was used to protect the volume encryption key for the parent volume. |
| AWS.EC2.Snapshot.OwnerId | string | The AWS account ID of the EBS snapshot owner. |
| AWS.EC2.Snapshot.Progress | string | The progress of the snapshot, as a percentage. |
| AWS.EC2.Snapshot.SnapshotId | string | The ID of the snapshot. |
| AWS.EC2.Snapshot.StartTime | date | The time stamp when the snapshot was initiated. |
| AWS.EC2.Snapshot.State | string | The snapshot state. |
| AWS.EC2.Snapshot.StateMessage | string | this field displays error state details to help you diagnose why the error occurred. |
| AWS.EC2.Snapshot.VolumeId | string | The ID of the volume that was used to create the snapshot. |
| AWS.EC2.Snapshot.VolumeSize | number | The size of the volume, in GiB. |
| AWS.EC2.Snapshot.OwnerAlias | string | Value from an Amazon-maintained list of snapshot owners. |
| AWS.EC2.Snapshot.Tags.Key | string | The key of the tag. |
| AWS.EC2.Snapshot.Tags.Value | string | The value of the tag. |
| AWS.EC2.Snapshot.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. |

### aws-ec2-instances-run

***
Launches a specified number of instances using an AMI you have access to. You can save time by creating a launch template containing your parameters and using the template instead of entering the parameters each time. An instance is ready for you to use when it is in the running state. You can check the state of your instance using aws-ec2-instances-describe.

#### Base Command

`aws-ec2-instances-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region where instances will be created. Must be a valid AWS region identifier. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| count | The number of instances to launch. Must be greater than 0. Default is 1. | Required |
| image_id | The ID of the AMI. An AMI ID is required to launch an instance and must be specified here or in a launch template. | Optional |
| instance_type | The instance type, for example: t2.large, t3.medium, m5.xlarge. | Optional |
| security_group_ids | A comma-separated list of security group IDs. Use this for VPC instances. If you don’t specify a security group ID, we use the default security group for the VPC. | Optional |
| security_groups_names | A comma-separated list of security group names. For a nondefault VPC, you must use security group IDs instead. | Optional |
| subnet_id | The ID of the subnet to launch the instance into. If you don't choose a subnet, we will use a default one from your default VPC. If you don't have a default VPC, you must specify a subnet ID yourself in the request. | Optional |
| user_data | The user data to make available to the instance. This value will be base64 encoded automatically. Do not base64 encode this value prior to performing the operation. | Optional |
| disable_api_termination | Indicates whether termination protection is enabled for the instance. The default is false, which means that you can terminate the instance using the Amazon EC2 console, command line tools, or API. Possible values are: true, false. Default is false. | Optional |
| iam_instance_profile_arn | The Amazon Resource Name (ARN) of the instance profile. Both iam_instance_profile_arn and iam_instance_profile_name are required if you would like to associate an instance profile. | Optional |
| iam_instance_profile_name | The name of the instance profile. Both iam_instance_profile_arn and iam_instance_profile_name are required if you would like to associate an instance profile. | Optional |
| key_name | The name of the key pair. Warning - If you do not specify a key pair, you can't connect to the instance unless you choose an AMI that is configured to allow users another way to log in. | Optional |
| ebs_optimized | Indicates whether the instance is optimized for Amazon EBS I/O. Possible values are: true, false. | Optional |
| device_name | The device name (for example, /dev/sdh or xvdh). If the argument is given, EBS arguments must also be specified. | Optional |
| ebs_volume_size | The size of the volume, in GiBs. You must specify either an ebs_snapshot_id or an ebs_volume_size. If you specify a snapshot, the default is the snapshot size. You can specify a volume size that is equal to or larger than the snapshot size. | Optional |
| ebs_volume_type | The volume type. Possible values are: gp2, gp3, io1, io2, st1, sc1, standard. | Optional |
| ebs_iops | The number of I/O operations per second (IOPS). For gp3, io1, and io2 volumes, this represents the number of IOPS that are provisioned for the volume. For gp2 volumes, this represents the baseline performance of the volume and the rate at which the volume accumulates I/O credits for bursting. This parameter is required for io1 and io2 volumes. The default for gp3 volumes is 3,000 IOPS. | Optional |
| ebs_delete_on_termination | Indicates whether the EBS volume is deleted on instance termination. Possible values are: true, false. | Optional |
| ebs_kms_key_id | Identifier (key ID, key alias, ID ARN, or alias ARN) for a user-managed CMK under which the EBS volume is encrypted. | Optional |
| ebs_snapshot_id | The ID of the snapshot. | Optional |
| ebs_encrypted | Indicates whether the encryption state of an EBS volume is changed while being restored from a backing snapshot. Possible values are: true, false. | Optional |
| launch_template_id | The ID of the launch template to use to launch the instances. Any parameters that you specify in the command override the same parameters in the launch template. You can specify either the name or ID of a launch template, but not both. | Optional |
| launch_template_name | The name of the launch template to use to launch the instances. Any parameters that you specify in the command override the same parameters in the launch template. You can specify either the name or ID of a launch template, but not both. | Optional |
| launch_template_version | The launch template version number, $Latest, or $Default. | Optional |
| tags | One or more tags to apply to a resource when the resource is being created, separated by ';' (for example, key=&lt;name&gt;;value=&lt;value&gt;). | Optional |
| host_id | The Dedicated Host ID. | Optional |
| enabled_monitoring | Indicates whether detailed monitoring is enabled. Otherwise, basic monitoring is enabled. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Instances.Architecture | String | The architecture of the image. |
| AWS.EC2.Instances.BlockDeviceMappings.DeviceName | String | The device name. |
| AWS.EC2.Instances.BlockDeviceMappings.Ebs | Dictionary | Parameters used to automatically set up EBS volumes when the instance is launched. |
| AWS.EC2.Instances.ClientToken | String | The idempotency token you provided when you launched the instance, if applicable. |
| AWS.EC2.Instances.EbsOptimized | Boolean | Indicates whether the instance is optimized for Amazon EBS I/O. |
| AWS.EC2.Instances.EnaSupport | Boolean | Specifies whether enhanced networking with ENA is enabled. |
| AWS.EC2.Instances.Hypervisor | String | The hypervisor type of the instance. |
| AWS.EC2.Instances.IamInstanceProfile.Arn | String | The Amazon Resource Name \(ARN\) of the instance profile. |
| AWS.EC2.Instances.IamInstanceProfile.Id | String | The ID of the instance profile. |
| AWS.EC2.Instances.InstanceLifecycle | String | Indicates whether this is a Spot Instance or a Scheduled Instance. |
| AWS.EC2.Instances.NetworkInterfaces.Association | Dictionary | The association information for an Elastic IPv4 associated with the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.Attachment | Dictionary | The network interface attachment. |
| AWS.EC2.Instances.NetworkInterfaces.Description | String | The description of the network interface. Applies only if creating a network interface when launching an instance. |
| AWS.EC2.Instances.NetworkInterfaces.Groups | Dictionary | The security groups. |
| AWS.EC2.Instances.NetworkInterfaces.Ipv6Addresses | Dictionary | The IPv6 addresses associated with the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.MacAddress | String | The MAC address. |
| AWS.EC2.Instances.NetworkInterfaces.NetworkInterfaceId | String | The ID of the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.OwnerId | String | The private DNS name. |
| AWS.EC2.Instances.NetworkInterfaces.PrivateDnsName | String | The IPv4 address of the network interface within the subnet. |
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddress | String | The IPv4 address of the network interface within the subnet. |
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses | Array | The private IPv4 addresses associated with the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.SourceDestCheck | Boolean | Indicates whether to validate network traffic to or from this network interface. |
| AWS.EC2.Instances.NetworkInterfaces.Status | String | The status of the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.SubnetId | String | The ID of the subnet associated with the network interface. Applies only if creating a network interface when launching an instance. |
| AWS.EC2.Instances.NetworkInterfaces.VpcId | String | The ID of the VPC. |
| AWS.EC2.Instances.NetworkInterfaces.InterfaceType | String | The type of network interface. |
| AWS.EC2.Instances.NetworkInterfaces.Ipv4Prefixes | Array | The IPv4 prefixes assigned to the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.Ipv6Prefixes | Array | The IPv6 prefixes assigned to the network interface. |
| AWS.EC2.Instances.NetworkInterfaces.ConnectionTrackingConfiguration | Dictionary | A security group connection tracking configuration that enables you to set the timeout for connection tracking on an Elastic network interface. |
| AWS.EC2.Instances.NetworkInterfaces.Operator | Dictionary | The service provider that manages the network interface. |
| AWS.EC2.Instances.OutpostArn | String | The Amazon Resource Name \(ARN\) of the Outpost. |
| AWS.EC2.Instances.RootDeviceName | String | The device name of the root device volume. |
| AWS.EC2.Instances.RootDeviceType | String | The root device type used by the AMI. |
| AWS.EC2.Instances.SecurityGroups.GroupId | String | The ID of the security group. |
| AWS.EC2.Instances.SecurityGroups.GroupName | String | The name of the security group. |
| AWS.EC2.Instances.SourceDestCheck | Boolean | Indicates whether source/destination checking is enabled. |
| AWS.EC2.Instances.SpotInstanceRequestId | String | The ID of the request for a Spot Instance request. |
| AWS.EC2.Instances.SriovNetSupport | String | Specifies whether enhanced networking with the Intel 82599 Virtual Function interface is enabled. |
| AWS.EC2.Instances.StateReason | Dictionary | The reason for the most recent state transition. May be an empty string. |
| AWS.EC2.Instances.Tags.Key | String | The key of the tag. |
| AWS.EC2.Instances.Tags.Value | String | The value of the tag. |
| AWS.EC2.Instances.VirtualizationType | String | The virtualization type of the instance. |
| AWS.EC2.Instances.CpuOptions | Dictionary | The CPU options for the instance. |
| AWS.EC2.Instances.CapacityBlockId | String | The ID of the Capacity Block. |
| AWS.EC2.Instances.CapacityReservationId | String | The ID of the Capacity Reservation. |
| AWS.EC2.Instances.CapacityReservationSpecification | Dictionary | Information about the Capacity Reservation targeting option. |
| AWS.EC2.Instances.HibernationOptions.Configured | Boolean | Indicates whether the instance is enabled for hibernation. |
| AWS.EC2.Instances.Licenses.LicenseConfigurationArn | String | The Amazon Resource Name \(ARN\) of the license configuration. |
| AWS.EC2.Instances.MetadataOptions | Dictionary | The metadata options for the instance. |
| AWS.EC2.Instances.EnclaveOptions.Enabled | Boolean | Indicates whether the instance is enabled for Amazon Web Services Nitro Enclaves. |
| AWS.EC2.Instances.BootMode | String | The boot mode that was specified by the AMI. |
| AWS.EC2.Instances.PlatformDetails | String | The platform details value for the instance. |
| AWS.EC2.Instances.UsageOperation | String | The usage operation value for the instance. |
| AWS.EC2.Instances.UsageOperationUpdateTime | Date | The time that the usage operation was last updated. |
| AWS.EC2.Instances.PrivateDnsNameOptions.HostnameType | String | The type of hostname to assign to an instance. |
| AWS.EC2.Instances.PrivateDnsNameOptions.EnableResourceNameDnsARecord | Boolean | Indicates whether to respond to DNS queries for instance hostnames with DNS A records. |
| AWS.EC2.Instances.PrivateDnsNameOptions.EnableResourceNameDnsAAAARecord | Boolean | Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records. |
| AWS.EC2.Instances.Ipv6Address | String | The IPv6 address assigned to the instance. |
| AWS.EC2.Instances.TpmSupport | String | If the instance is configured for NitroTPM support, the value is v2.0. |
| AWS.EC2.Instances.MaintenanceOptions.AutoRecovery | String | Information on the current automatic recovery behavior of your instance. |
| AWS.EC2.Instances.MaintenanceOptions.RebootMigration | String | Specifies whether to attempt reboot migration during a user-initiated reboot of an instance that has a scheduled system-reboot event. |
| AWS.EC2.Instances.CurrentInstanceBootMode | String | The boot mode that is used to boot the instance at launch or start. |
| AWS.EC2.Instances.NetworkPerformanceOptions.BandwidthWeighting | String | Contains settings for the network performance options for your instance. |
| AWS.EC2.Instances.Operator | Dictionary | The service provider that manages the instance. |
| AWS.EC2.Instances.InstanceId | String | The ID of the instance. |
| AWS.EC2.Instances.ImageId | String | The ID of the AMI used to launch the instance. |
| AWS.EC2.Instances.State.Code | Number | The current state of the instance as a 16-bit unsigned integer. |
| AWS.EC2.Instances.State.Name | String | The current state of the instance. |
| AWS.EC2.Instances.PrivateDnsName | String | The private DNS hostname name assigned to the instance. |
| AWS.EC2.Instances.PublicDnsName | String | The public DNS name assigned to the instance. |
| AWS.EC2.Instances.StateTransitionReason | String | The reason for the most recent state transition. May be an empty string. |
| AWS.EC2.Instances.KeyName | String | The name of the key pair used when the instance was launched. |
| AWS.EC2.Instances.AmiLaunchIndex | Number | The AMI launch index, which can be used to find this instance in the launch group. |
| AWS.EC2.Instances.ProductCodes | Dictionary | The product codes attached to this instance, if applicable. |
| AWS.EC2.Instances.InstanceType | String | The instance type. |
| AWS.EC2.Instances.LaunchTime | String | The time the instance was launched. |
| AWS.EC2.Instances.Placement.AvailabilityZoneId | String | The ID of the Availability Zone of the instance. |
| AWS.EC2.Instances.Placement.Affinity | String | The affinity setting for the instance on the Dedicated Host. |
| AWS.EC2.Instances.Placement.GroupName | String | The name of the placement group the instance is in. |
| AWS.EC2.Instances.Placement.PartitionNumber | Number | The number of the partition that the instance is in. |
| AWS.EC2.Instances.Placement.HostId | String | The ID of the Dedicated Host on which the instance resides. |
| AWS.EC2.Instances.Placement.Tenancy | String | The tenancy of the instance. |
| AWS.EC2.Instances.Placement.HostResourceGroupArn | String | The ARN of the host resource group in which to launch the instances. |
| AWS.EC2.Instances.Placement.GroupId | String | The ID of the placement group that the instance is in. |
| AWS.EC2.Instances.Placement.AvailabilityZone | String | The availability zone of the instance. |
| AWS.EC2.Instances.KernelId | String | The kernel associated with this instance, if applicable. |
| AWS.EC2.Instances.RamdiskId | String | The RAM disk associated with this instance, if applicable. |
| AWS.EC2.Instances.Platform | String | The platform the instance uses. The value is Windows for Windows instances; otherwise, blank. |
| AWS.EC2.Instances.Monitoring.State | String | Indicates whether detailed monitoring is enabled. |
| AWS.EC2.Instances.SubnetId | String | The ID of the subnet in which the instance is running. |
| AWS.EC2.Instances.VpcId | String | The ID of the VPC in which the instance is running. |
| AWS.EC2.Instances.PrivateIpAddress | String | The private IPv4 address assigned to the instance. |
| AWS.EC2.Instances.PublicIpAddress | String | The public IPv4 address assigned to the instance. |

### aws-rds-event-subscription-modify

***
Modifies an existing RDS event notification subscription.

#### Base Command

`aws-rds-event-subscription-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| subscription_name | The name of the RDS event notification subscription. | Required |
| enabled | Specifies whether to activate the subscription. | Optional |
| event_categories | A list of event categories for a source type (SourceType) that you want to subscribe to. | Optional |
| sns_topic_arn | The Amazon Resource Name (ARN) of the SNS topic created for event notification. | Optional |
| source_type | The type of source that is generating the events. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.RDS.EventSubscription.CustomerAwsId | string | The AWS customer account associated with the RDS event notification subscription. |
| AWS.RDS.EventSubscription.CustSubscriptionId | string | The RDS event notification subscription Id. |
| AWS.RDS.EventSubscription.Enabled | boolean | Specifies whether the subscription is enabled. True indicates the subscription is enabled. |
| AWS.RDS.EventSubscription.EventCategoriesList | array | A list of event categories for the RDS event notification subscription. |
| AWS.RDS.EventSubscription.EventSubscriptionArn | string | The Amazon Resource Name \(ARN\) for the event subscription. |
| AWS.RDS.EventSubscription.SnsTopicArn | string | The topic ARN of the RDS event notification subscription. |
| AWS.RDS.EventSubscription.SourceIdsList | array | A list of source IDs for the RDS event notification subscription. |
| AWS.RDS.EventSubscription.SourceType | string | The source type for the RDS event notification subscription. |
| AWS.RDS.EventSubscription.Status | string | The status of the RDS event notification subscription. |
| AWS.RDS.EventSubscription.SubscriptionCreationTime | string | The time the RDS event notification subscription was created. |

### aws-ec2-snapshot-permission-modify

***
Adds or removes permission settings for the specified snapshot.

#### Base Command

`aws-ec2-snapshot-permission-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| snapshot_id | The ID of the EBS snapshot. | Required |
| operation_type | The operation type, add or remove. Possible values are: add, remove. | Required |
| group_names | CSV of security group names. This parameter can be used only when UserIds not provided. | Optional |
| user_ids | CSV of AWS account IDs. This parameter can be used only when groupNames not provided. | Optional |
| dry_run | Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. Possible values are: True, False. | Optional |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

There is no context output for this command.

### aws-s3-bucket-website-delete

***
Removes the website configuration for a bucket.

#### Base Command

`aws-s3-bucket-website-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| bucket | The name of the S3 bucket from which the website configuration will be removed. | Required |

#### Context Output

There is no context output for this command.

### aws-s3-bucket-ownership-controls-put

***
Creates or modifies OwnershipControls for an Amazon S3 bucket.

#### Base Command

`aws-s3-bucket-ownership-controls-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| bucket | The name of the Amazon S3 bucket for which to configure Ownership Controls. | Required |
| ownership_controls_rule | Ownership for a bucket's ownership controls. Possible values are: BucketOwnerPreferred, ObjectWriter, BucketOwnerEnforced. | Required |

#### Context Output

There is no context output for this command.

### aws-eks-cluster-describe

***
Describes an Amazon EKS cluster.

#### Base Command

`aws-eks-cluster-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| cluster_name | The name of the cluster to describe. | Required |
| region | The AWS Region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EKS.Cluster.name | String | The name of your cluster. |
| AWS.EKS.Cluster.arn | String | The Amazon Resource Name \(ARN\) of the cluster. |
| AWS.EKS.Cluster.createdAt | String | The creation date of the object. |
| AWS.EKS.Cluster.version | String | The Kubernetes server version for the cluster. |
| AWS.EKS.Cluster.endpoint | String | The endpoint for your Kubernetes API server. |
| AWS.EKS.Cluster.roleArn | String | The Amazon Resource Name \(ARN\) of the IAM role that provides permissions for the Kubernetes control plane to make calls to Amazon Web Services API operations on your behalf. |
| AWS.EKS.Cluster.resourcesVpcConfig.subnetIds | List | The subnets associated with your cluster. |
| AWS.EKS.Cluster.resourcesVpcConfig.securityGroupIds | List | The security groups associated with the cross-account elastic network interfaces that are used to allow communication between your nodes and the Kubernetes control plane. |
| AWS.EKS.Cluster.resourcesVpcConfig.clusterSecurityGroupId | String | The cluster security group that was created by Amazon EKS for the cluster. Managed node groups use this security group for control-plane-to-data-plane communication. |
| AWS.EKS.Cluster.resourcesVpcConfig.vpcId | String | The VPC associated with your cluster. |
| AWS.EKS.Cluster.resourcesVpcConfig.endpointPublicAccess | Boolean | Whether the public API server endpoint is enabled. |
| AWS.EKS.Cluster.resourcesVpcConfig.endpointPrivateAccess | Boolean | This parameter indicates whether the Amazon EKS private API server endpoint is enabled. |
| AWS.EKS.Cluster.resourcesVpcConfig.publicAccessCidrs | List | The CIDR blocks that are allowed access to your cluster’s public Kubernetes API server endpoint. |
| AWS.EKS.Cluster.kubernetesNetworkConfig.serviceIpv4Cidr | String | The CIDR block that Kubernetes Pod and Service object IP addresses are assigned from. |
| AWS.EKS.Cluster.kubernetesNetworkConfig.serviceIpv6Cidr | String | The CIDR block that Kubernetes Pod and Service IP addresses are assigned from if you created a 1.21 or later cluster with version 1.10.1 or later of the Amazon VPC CNI add-on and specified ipv6 for ipFamily when you created the cluster. |
| AWS.EKS.Cluster.kubernetesNetworkConfig.ipFamily | String | The IP family used to assign Kubernetes Pod and Service objects IP addresses. |
| AWS.EKS.Cluster.logging.clusterLogging | Object | The cluster control plane logging configuration for your cluster. |
| AWS.EKS.Cluster.identity | Object | The identity provider information for the cluster. |
| AWS.EKS.Cluster.status | String | The current status of the cluster. |
| AWS.EKS.Cluster.certificateAuthority.data | String | The Base64-encoded certificate data required to communicate with your cluster. |
| AWS.EKS.Cluster.clientRequestToken | String | A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. |
| AWS.EKS.Cluster.platformVersion | String | The platform version of your Amazon EKS cluster. |
| AWS.EKS.Cluster.tags | Object | A dictionary containing metadata for categorization and organization. |
| AWS.EKS.Cluster.encryptionConfig.resources | List | Specifies the resources to be encrypted. The only supported value is secrets. |
| AWS.EKS.Cluster.encryptionConfig.provider | Object | Key Management Service \(KMS\) key. |
| AWS.EKS.Cluster.connectorConfig.activationId | String | A unique ID associated with the cluster for registration purposes. |
| AWS.EKS.Cluster.connectorConfig.activationCode | String | A unique code associated with the cluster for registration purposes. |
| AWS.EKS.Cluster.connectorConfig.activationExpiry | String | The expiration time of the connected cluster. |
| AWS.EKS.Cluster.connectorConfig.provider | String | The cluster’s cloud service provider. |
| AWS.EKS.Cluster.connectorConfig.roleArn | String | The Amazon Resource Name \(ARN\) of the role to communicate with services from the connected Kubernetes cluster. |
| AWS.EKS.Cluster.id | String | The ID of your local Amazon EKS cluster on an Amazon Web Services Outpost. |
| AWS.EKS.Cluster.health.issues | List | An object representing the health issues of your local Amazon EKS cluster on an Amazon Web Services Outpost. |
| AWS.EKS.Cluster.outpostConfig.outpostArns | Object | An object representing the configuration of your local Amazon EKS cluster on an Amazon Web Services Outpost. |
| AWS.EKS.Cluster.outpostConfig.controlPlaneInstanceType | String | The Amazon EC2 instance type used for the control plane. |
| AWS.EKS.Cluster.outpostConfig.controlPlanePlacement | Object | An object representing the placement configuration for all the control plane instances of your local Amazon EKS cluster on an Amazon Web Services Outpost. |
| AWS.EKS.Cluster.accessConfig.bootstrapClusterCreatorAdminPermissions | Boolean | Specifies whether or not the cluster creator IAM principal was set as a cluster admin access entry during cluster creation time. |
| AWS.EKS.Cluster.accessConfig.authenticationMode | String | The current authentication mode of the cluster. |

### aws-eks-access-policy-associate

***
Associates an access policy and its scope to an access entry.

#### Base Command

`aws-eks-access-policy-associate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| cluster_name | The name of the cluster for which to create an access entry. | Required |
| principal_arn | The Amazon Resource Name (ARN) of the IAM user or role for the AccessEntry that you’re associating the access policy to. | Required |
| policy_arn | The ARN of the AccessPolicy that you’re associating. | Required |
| type | The scope type of an access policy. Possible values are: cluster, namespace. | Required |
| namespaces | A comma-separated list of Kubernetes namespaces that an access policy is scoped to. A value is required if you specified namespace for type. | Optional |
| region | The AWS Region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EKS.AssociatedAccessPolicy.clusterName | String | The name of your cluster. |
| AWS.EKS.AssociatedAccessPolicy.principalArn | String | The ARN of the IAM principal for the AccessEntry. |
| AWS.EKS.AssociatedAccessPolicy.policyArn | String | The ARN of the AccessPolicy. |
| AWS.EKS.AssociatedAccessPolicy.accessScope.type | String | The scope type of an access policy. |
| AWS.EKS.AssociatedAccessPolicy.accessScope.namespaces | String | A Kubernetes namespace that an access policy is scoped to. |
| AWS.EKS.AssociatedAccessPolicy.associatedAt | String | The date and time the AccessPolicy was associated with an AccessEntry. |
| AWS.EKS.AssociatedAccessPolicy.modifiedAt | String | The date and time for the last modification to the object. |

### aws-billing-cost-usage-list

***
Retrieves actual cost and usage data for a given time range and optional service filter.

#### Base Command

`aws-billing-cost-usage-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account on which to run the command. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| metrics | Metrics to retrieve. Default - UsageQuantity. Valid values [AmortizedCost, BlendedCost, NetAmortizedCost, NetUnblendedCost, NormalizedUsageAmount, UnblendedCost, UsageQuantity]. | Optional |
| start_date | Start date for the report (YYYY-MM-DD). Default - 7 days ago. | Optional |
| end_date | End date for the report (YYYY-MM-DD). Default - current day. | Optional |
| granularity | Granularity of the data. Default - Daily. Valid values [Daily, Monthly, Hourly]. Possible values are: Daily, Monthly, Hourly. | Optional |
| aws_services | Optional filter for retrieving data for specific AWS services. | Optional |
| next_page_token | Next page token for pagination. Use value from AWS.Billing.UsageNextToken. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Billing.Usage | unknown | Complete usage data from AWS Cost Explorer API. |
| AWS.Billing.Usage.TimePeriod | unknown | Time period for the usage data. |
| AWS.Billing.Usage.TimePeriod.Start | date | Start date of the time period. |
| AWS.Billing.Usage.TimePeriod.End | date | End date of the time period. |
| AWS.Billing.Usage.Total | unknown | Total cost and usage metrics for the time period. |
| AWS.Billing.Usage.Total.AmortizedCost | unknown | Amortized cost information. |
| AWS.Billing.Usage.Total.AmortizedCost.Amount | string | Amortized cost amount. |
| AWS.Billing.Usage.Total.AmortizedCost.Unit | string | Amortized cost unit \(e.g., USD\). |
| AWS.Billing.Usage.Total.BlendedCost | unknown | Blended cost information. |
| AWS.Billing.Usage.Total.BlendedCost.Amount | string | Blended cost amount. |
| AWS.Billing.Usage.Total.BlendedCost.Unit | string | Blended cost unit \(e.g., USD\). |
| AWS.Billing.Usage.Total.NetAmortizedCost | unknown | Net amortized cost information. |
| AWS.Billing.Usage.Total.NetAmortizedCost.Amount | string | Net amortized cost amount. |
| AWS.Billing.Usage.Total.NetAmortizedCost.Unit | string | Net amortized cost unit \(e.g., USD\). |
| AWS.Billing.Usage.Total.NetUnblendedCost | unknown | Net unblended cost information. |
| AWS.Billing.Usage.Total.NetUnblendedCost.Amount | string | Net unblended cost amount. |
| AWS.Billing.Usage.Total.NetUnblendedCost.Unit | string | Net unblended cost unit \(e.g., USD\). |
| AWS.Billing.Usage.Total.NormalizedUsageAmount | unknown | Normalized usage amount information. |
| AWS.Billing.Usage.Total.NormalizedUsageAmount.Amount | string | Normalized usage amount. |
| AWS.Billing.Usage.Total.NormalizedUsageAmount.Unit | string | Normalized usage amount unit. |
| AWS.Billing.Usage.Total.UnblendedCost | unknown | Unblended cost information. |
| AWS.Billing.Usage.Total.UnblendedCost.Amount | string | Unblended cost amount. |
| AWS.Billing.Usage.Total.UnblendedCost.Unit | string | Unblended cost unit \(e.g., USD\). |
| AWS.Billing.Usage.Total.UsageQuantity | unknown | Usage quantity information. |
| AWS.Billing.Usage.Total.UsageQuantity.Amount | string | Usage quantity amount. |
| AWS.Billing.Usage.Total.UsageQuantity.Unit | string | Usage quantity unit \(e.g., Hrs, GB\). |
| AWS.Billing.Usage.Groups | unknown | Usage data grouped by dimensions \(when grouping is applied\). |
| AWS.Billing.Usage.Groups.Keys | unknown | Group keys \(dimension values\). |
| AWS.Billing.Usage.Groups.Metrics | unknown | Metrics for the group. |
| AWS.Billing.Usage.Estimated | boolean | Whether the data is estimated. |
| AWS.Billing.UsageNextToken | string | Next page token for pagination. |

### aws-billing-forecast-list

***
Forecasts AWS spending over a given future time period using historical trends.

#### Base Command

`aws-billing-forecast-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account on which to run the command. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| metric | Metric to forecast. Valid values [AMORTIZED_COST, BLENDED_COST, NET_AMORTIZED_COST, NET_UNBLENDED_COST, UNBLENDED_COST]. Possible values are: AMORTIZED_COST, BLENDED_COST, NET_AMORTIZED_COST, NET_UNBLENDED_COST, UNBLENDED_COST. Default is AMORTIZED_COST. | Optional |
| start_date | Start date for the forecast (YYYY-MM-DD). Default - current day. | Optional |
| end_date | End date for the forecast (YYYY-MM-DD). Default - in 7 days. | Optional |
| granularity | Granularity of the forecast. Default - Daily. Valid values [ Daily, Monthly, Hourly]. Possible values are: Daily, Monthly, Hourly. | Optional |
| aws_services | Optional filter for retrieving data for specific AWS services. | Optional |
| next_page_token | Next page token for pagination. Use value from AWS.Billing.ForecastNextToken. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Billing.Forecast | unknown | Complete forecast data from AWS Cost Explorer API. |
| AWS.Billing.Forecast.Service | string | AWS Service \(if exists\). |
| AWS.Billing.Forecast.StartDate | date | Start date of the forecast. |
| AWS.Billing.Forecast.EndDate | date | End date of the forecast. |
| AWS.Billing.Forecast.TotalAmount | string | Total forecasted amount. |
| AWS.Billing.Forecast.TotalUnit | string | Unit for the forecasted amount. |
| AWS.Billing.Forecast.ForecastResultsByTime | unknown | Forecast results grouped by time period. |
| AWS.Billing.Forecast.ForecastResultsByTime.TimePeriod | unknown | Time period for the forecast. |
| AWS.Billing.Forecast.ForecastResultsByTime.TimePeriod.Start | date | Start date of the forecast period. |
| AWS.Billing.Forecast.ForecastResultsByTime.TimePeriod.End | date | End date of the forecast period. |
| AWS.Billing.Forecast.ForecastResultsByTime.MeanValue | string | Mean forecasted value for the time period. |
| AWS.Billing.Forecast.ForecastResultsByTime.PredictionIntervalLowerBound | string | Lower bound of the prediction interval. |
| AWS.Billing.Forecast.ForecastResultsByTime.PredictionIntervalUpperBound | string | Upper bound of the prediction interval. |
| AWS.Billing.Forecast.Total | unknown | Total forecast information. |
| AWS.Billing.Forecast.Total.Amount | string | Total forecasted amount. |
| AWS.Billing.Forecast.Total.Unit | string | Unit for the total forecasted amount. |
| AWS.Billing.ForecastNextToken | string | Next page token for pagination. |

### aws-billing-budgets-list

***
Lists configured budgets for a given AWS account.

#### Base Command

`aws-billing-budgets-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account on which to run the command. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| max_result | Maximum results to return. Default - 50, Max - 1000. Default is 50. | Optional |
| show_filter_expression | Whether to show filter expression. Default - False. Possible values are: true, false. Default is false. | Optional |
| next_page_token | Next page token for pagination. Use value from AWS.Billing.BudgetNextToken. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Billing.Budget | unknown | Complete budget data from AWS Budgets API. |
| AWS.Billing.Budget.BudgetName | string | Budget name. |
| AWS.Billing.Budget.BudgetType | string | Budget type \(COST, USAGE, RI_UTILIZATION, RI_COVERAGE, SAVINGS_PLANS_UTILIZATION, SAVINGS_PLANS_COVERAGE\). |
| AWS.Billing.Budget.TimeUnit | string | Time unit for the budget \(DAILY, MONTHLY, QUARTERLY, ANNUALLY\). |
| AWS.Billing.Budget.TimePeriod | unknown | Time period for the budget. |
| AWS.Billing.Budget.TimePeriod.Start | date | Start date of the budget time period. |
| AWS.Billing.Budget.TimePeriod.End | date | End date of the budget time period. |
| AWS.Billing.Budget.BudgetLimit | unknown | Budget limit configuration. |
| AWS.Billing.Budget.BudgetLimit.Amount | string | Budget limit amount. |
| AWS.Billing.Budget.BudgetLimit.Unit | string | Budget limit unit \(e.g., USD\). |
| AWS.Billing.Budget.CostFilters | unknown | Cost filters applied to the budget. |
| AWS.Billing.Budget.TimeUnit | string | Time unit for the budget period. |
| AWS.Billing.Budget.CalculatedSpend | unknown | Calculated spend information. |
| AWS.Billing.Budget.CalculatedSpend.ActualSpend | unknown | Actual spend information. |
| AWS.Billing.Budget.CalculatedSpend.ActualSpend.Amount | string | Actual spend amount. |
| AWS.Billing.Budget.CalculatedSpend.ActualSpend.Unit | string | Actual spend unit \(e.g., USD\) |
| AWS.Billing.Budget.CalculatedSpend.ForecastedSpend | unknown | Forecasted spend information. |
| AWS.Billing.Budget.CalculatedSpend.ForecastedSpend.Amount | string | Forecasted spend amount. |
| AWS.Billing.Budget.CalculatedSpend.ForecastedSpend.Unit | string | Forecasted spend unit \(e.g., USD\). |
| AWS.Billing.Budget.BudgetType | string | Type of budget \(COST, USAGE, etc.\). |
| AWS.Billing.Budget.LastUpdatedTime | date | Last time the budget was updated. |
| AWS.Billing.Budget.AutoAdjustData | unknown | Auto-adjust data for the budget. |
| AWS.Billing.Budget.PlannedBudgetLimits | unknown | Planned budget limits for future periods. |
| AWS.Billing.BudgetNextToken | string | Next page token for pagination. |

### aws-billing-budget-notification-list

***
Lists the notifications that are associated with a budget.

#### Base Command

`aws-billing-budget-notification-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | AWS account to run the command on. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1. | Required |
| budget_name | Name of the budget. | Required |
| max_result | Maximum results to return. Default - 50, Max - 100. Default is 50. | Optional |
| next_page_token | Next page token for pagination. Use value from AWS.Billing.NotificationNextToken. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Billing.Budget.Notification | unknown | Complete budget notification data from AWS Budgets API. |
| AWS.Billing.Budget.Notification.Notification | unknown | Notification configuration. |
| AWS.Billing.Budget.Notification.Notification.NotificationType | string | Type of notification \(ACTUAL or FORECASTED\). |
| AWS.Billing.Budget.Notification.Notification.ComparisonOperator | string | Comparison operator for the notification \(GREATER_THAN, LESS_THAN, EQUAL_TO\). |
| AWS.Billing.Budget.Notification.Notification.Threshold | number | Threshold value that triggers the notification. |
| AWS.Billing.Budget.Notification.Notification.ThresholdType | string | Type of threshold \(PERCENTAGE or ABSOLUTE_VALUE\). |
| AWS.Billing.Budget.Notification.Notification.NotificationState | string | Current state of the notification \(OK or ALARM\). |
| AWS.Billing.Budget.Notification.Subscribers | unknown | List of subscribers for the notification. |
| AWS.Billing.Budget.Notification.Subscribers.SubscriptionType | string | Subscription type \(EMAIL or SNS\). |
| AWS.Billing.Budget.Notification.Subscribers.Address | string | Email address or SNS topic ARN for the subscriber. |
| AWS.Billing.NotificationNextToken | string | Next page token for pagination. |

### aws-lambda-function-configuration-get

***
Retrieves configuration information about a Lambda function.

#### Base Command

`aws-lambda-function-configuration-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| function_name | Name, ARN, or qualified name of the Lambda function. | Required |
| qualifier | Version number or alias name. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.FunctionConfig.FunctionName | String | The name of the function. |
| AWS.Lambda.FunctionConfig.FunctionArn | String | The function’s Amazon Resource Name \(ARN\). |
| AWS.Lambda.FunctionConfig.Runtime | String | The identifier of the function’s runtime. |
| AWS.Lambda.FunctionConfig.Role | String | The function’s execution role. |
| AWS.Lambda.FunctionConfig.Handler | String | The function that Lambda calls to begin running your function. |
| AWS.Lambda.FunctionConfig.CodeSize | Number | The size of the function’s deployment package, in bytes. |
| AWS.Lambda.FunctionConfig.Description | String | The function’s description. |
| AWS.Lambda.FunctionConfig.Timeout | Number | The amount of time in seconds that Lambda allows a function to run before stopping it. |
| AWS.Lambda.FunctionConfig.MemorySize | Number | The amount of memory available to the function at runtime. |
| AWS.Lambda.FunctionConfig.LastModified | String | The date and time that the function was last updated. |
| AWS.Lambda.FunctionConfig.CodeSha256 | String | The SHA256 hash of the function’s deployment package. |
| AWS.Lambda.FunctionConfig.Version | String | The version of the Lambda function. |
| AWS.Lambda.FunctionConfig.VpcConfig.SubnetIds | unknown | A list of VPC subnet IDs. |
| AWS.Lambda.FunctionConfig.VpcConfig.SecurityGroupIds | unknown | A list of VPC security group IDs. |
| AWS.Lambda.FunctionConfig.VpcConfig.VpcId | String | The ID of the VPC. |
| AWS.Lambda.FunctionConfig.VpcConfig.Ipv6AllowedForDualStack | Boolean | Allows outbound IPv6 traffic on VPC functions that are connected to dual-stack subnets. |
| AWS.Lambda.FunctionConfig.DeadLetterConfig.TargetArn | String | The Amazon Resource Name \(ARN\) of an Amazon SQS queue or Amazon SNS topic. |
| AWS.Lambda.FunctionConfig.Environment.Variables | unknown | Environment variable key-value pairs. Omitted from CloudTrail logs. |
| AWS.Lambda.FunctionConfig.Environment.Error.ErrorCode | String | The error code. |
| AWS.Lambda.FunctionConfig.Environment.Error.Message | String | The error message. |
| AWS.Lambda.FunctionConfig.KMSKeyArn | String | The ARN of the Key Management Service \(KMS\). |
| AWS.Lambda.FunctionConfig.TracingConfig.Mode | String | The tracing mode. |
| AWS.Lambda.FunctionConfig.MasterArn | String | For Lambda@Edge functions, the ARN of the main function. |
| AWS.Lambda.FunctionConfig.RevisionId | String | The latest updated revision of the function or alias. |
| AWS.Lambda.FunctionConfig.Layers.Arn | String | The Amazon Resource Name \(ARN\) of the function layer. |
| AWS.Lambda.FunctionConfig.Layers.CodeSize | Number | The size of the layer archive in bytes. |
| AWS.Lambda.FunctionConfig.Layers.SigningProfileVersionArn | String | The Amazon Resource Name \(ARN\) for a signing profile version. |
| AWS.Lambda.FunctionConfig.Layers.SigningJobArn | String | The Amazon Resource Name \(ARN\) of a signing job. |
| AWS.Lambda.FunctionConfig.State | String | The current state of the function. |
| AWS.Lambda.FunctionConfig.StateReason | String | The reason for the function’s current state. |
| AWS.Lambda.FunctionConfig.StateReasonCode | String | The reason code for the function’s current state. |
| AWS.Lambda.FunctionConfig.LastUpdateStatus | String | The status of the last update that was performed on the function. |
| AWS.Lambda.FunctionConfig.LastUpdateStatusReason | String | The reason for the last update that was performed on the function. |
| AWS.Lambda.FunctionConfig.LastUpdateStatusReasonCode | String | The reason code for the last update that was performed on the function. |
| AWS.Lambda.FunctionConfig.FileSystemConfigs.Arn | String | The Amazon Resource Name \(ARN\) of the Amazon EFS access point that provides access to the file system. |
| AWS.Lambda.FunctionConfig.FileSystemConfigs.LocalMountPath | String | The path where the function can access the file system, starting with /mnt/. |
| AWS.Lambda.FunctionConfig.PackageType | String | The type of deployment package. |
| AWS.Lambda.FunctionConfig.ImageConfigResponse.ImageConfig.EntryPoint | String | Specifies the entry point to their application, which is typically the location of the runtime executable. |
| AWS.Lambda.FunctionConfig.ImageConfigResponse.ImageConfig.Command | String | Specifies parameters that you want to pass in with ENTRYPOINT. |
| AWS.Lambda.FunctionConfig.ImageConfigResponse.ImageConfig.WorkingDirectory | String | Specifies the working directory. |
| AWS.Lambda.FunctionConfig.ImageConfigResponse.Error.ErrorCode | String | Error code. |
| AWS.Lambda.FunctionConfig.ImageConfigResponse.Error.Message | String | Error message. |
| AWS.Lambda.FunctionConfig.SigningProfileVersionArn | String | The ARN of the signing profile version. |
| AWS.Lambda.FunctionConfig.SigningJobArn | String | The ARN of the signing job. |
| AWS.Lambda.FunctionConfig.Architectures | String | The size of the function’s /tmp directory in MB. |
| AWS.Lambda.FunctionConfig.EphemeralStorage.Size | Number | The size of the function’s /tmp directory. |
| AWS.Lambda.FunctionConfig.SnapStart.ApplyOn | String | When set to PublishedVersions, Lambda creates a snapshot of the execution environment when you publish a function version. |
| AWS.Lambda.FunctionConfig.SnapStart.OptimizationStatus | String | When you provide a qualified Amazon Resource Name \(ARN\), this response element indicates whether SnapStart is activated for the specified function version. |
| AWS.Lambda.FunctionConfig.RuntimeVersionConfig.RuntimeVersionArn | String | The ARN of the runtime version you want the function to use. |
| AWS.Lambda.FunctionConfig.RuntimeVersionConfig.Error.ErrorCode | String | The error code. |
| AWS.Lambda.FunctionConfig.RuntimeVersionConfig.Error.Message | String | The error message. |
| AWS.Lambda.FunctionConfig.LoggingConfig.LogFormat | String | The format in which Lambda sends your function’s application and system logs to CloudWatch. |
| AWS.Lambda.FunctionConfig.LoggingConfig.ApplicationLogLevel | String | Set this property to filter the application logs for your function that Lambda sends to CloudWatch. |
| AWS.Lambda.FunctionConfig.LoggingConfig.SystemLogLevel | String | Set this property to filter the system logs for your function that Lambda sends to CloudWatch. |
| AWS.Lambda.FunctionConfig.LoggingConfig.LogGroup | String | The name of the Amazon CloudWatch log group the function sends logs to. |

### aws-lambda-function-url-config-get

***
Returns the configuration for a Lambda function URL.

#### Base Command

`aws-lambda-function-url-config-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| function_name | Name of the Lambda function. | Required |
| qualifier | The alias name or version number. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.FunctionURLConfig.FunctionUrl | String | The HTTP URL endpoint for your function. |
| AWS.Lambda.FunctionURLConfig.FunctionArn | String | The Amazon Resource Name \(ARN\) of your function. |
| AWS.Lambda.FunctionURLConfig.AuthType | String | The type of authentication that your function URL uses. |
| AWS.Lambda.FunctionURLConfig.Cors.AllowCredentials | Boolean | Whether to allow cookies or other credentials in requests to your function URL. |
| AWS.Lambda.FunctionURLConfig.Cors.AllowHeaders | String | The HTTP headers that origins can include in requests to your function URL. |
| AWS.Lambda.FunctionURLConfig.Cors.AllowMethods | String | The HTTP methods that are allowed when calling your function URL. |
| AWS.Lambda.FunctionURLConfig.Cors.AllowOrigins | String | The origins that can access your function URL. |
| AWS.Lambda.FunctionURLConfig.Cors.ExposeHeaders | String | The HTTP headers in your function response that you want to expose to origins that call your function URL. |
| AWS.Lambda.FunctionURLConfig.Cors.MaxAge | Number | The maximum amount of time, in seconds, that web browsers can cache results of a preflight request. |
| AWS.Lambda.FunctionURLConfig.CreationTime | String | When the function URL was created. |
| AWS.Lambda.FunctionURLConfig.LastModifiedTime | String | When the function URL configuration was last updated. |
| AWS.Lambda.FunctionURLConfig.InvokeMode | String | BUFFERED or RESPONSE_STREAM. |

### aws-lambda-policy-get

***
Returns the resource-based IAM policy for a Lambda function.

#### Base Command

`aws-lambda-policy-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| function_name | Name of the Lambda function, version, or alias. | Required |
| qualifier | Version or alias to get the policy for. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.Policy.Version | Date | The policy version. |
| AWS.Lambda.Policy.Id | String | The identifier of the policy. |
| AWS.Lambda.Policy.Statement.Sid | String | Identifier of the policy statement. |
| AWS.Lambda.Policy.Statement.Effect | String | Specifies whether the statement results in an allow or an explicit deny. |
| AWS.Lambda.Policy.Statement.Principal | unknown | Specify the principal that is allowed or denied access to a resource. |
| AWS.Lambda.Policy.Statement.Action | unknown | Describes the specific action or actions that will be allowed or denied. |
| AWS.Lambda.Policy.Statement.Resource | unknown | Defines the object or objects that the statement applies to. |
| AWS.Lambda.Policy.Statement.Condition | String | Specify conditions for when a policy is in effect. |
| AWS.Lambda.Policy.RevisionId | String | A unique identifier for the current revision of the policy. |
| AWS.Lambda.Policy.AccountId | String | The AWS account ID. |
| AWS.Lambda.Policy.FunctionName | String | The Function Name. |
| AWS.Lambda.Policy.Region | String | The AWS Region. |

### aws-lambda-invoke

***
Invokes a Lambda function. Specify just a function name to invoke the latest version of the function. To invoke a published version, use the Qualifier parameter to specify a version or alias. If you use the RequestResponse (synchronous) invocation option, note that the function may be invoked multiple times if a timeout is reached. For functions with a long timeout, your client may be disconnected during synchronous invocation while it waits for a response. If you use the Event (asynchronous) invocation option, the function will be invoked at least once in response to an event and the function must be idempotent to handle this.

#### Base Command

`aws-lambda-invoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| function_name | Name of the Lambda function to invoke. | Required |
| invocation_type | RequestResponse (sync), Event (async), or DryRun. Default is RequestResponse. Possible values are: RequestResponse, Event, DryRun. Default is RequestResponse. | Optional |
| log_type | Set to Tail to include execution log in response. Possible values are: None, Tail. | Optional |
| client_context | Base64-encoded client context data. | Optional |
| payload | JSON input to provide to the Lambda function. | Optional |
| qualifier | Version or alias to invoke. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.InvokedFunction.StatusCode | Number | The HTTP status code is in the 200 range for a successful request. |
| AWS.Lambda.InvokedFunction.FunctionError | String | If present, indicates that an error occurred during function execution. |
| AWS.Lambda.InvokedFunction.LogResult | String | The last 4 KB of the execution log, which is base64-encoded. |
| AWS.Lambda.InvokedFunction.Payload | Unknown | The response from the function, or an error object. |
| AWS.Lambda.InvokedFunction.ExecutedVersion | String | The version of the function that executed. |
| AWS.Lambda.InvokedFunction.FunctionName | string | The name of the Lambda function. |

### aws-lambda-function-url-config-update

***
Updates the configuration for a Lambda function URL.

#### Base Command

`aws-lambda-function-url-config-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| function_name | Name of the Lambda function. | Required |
| qualifier | The alias name or version number. | Optional |
| auth_type | AWS_IAM or NONE for authentication type. Possible values are: AWS_IAM, NONE. | Optional |
| cors_allow_credentials | Allow credentials in CORS requests. Possible values are: true, false. | Optional |
| cors_allow_headers | Comma-separated list of allowed headers. | Optional |
| cors_allow_methods | Comma-separated list of allowed HTTP methods. | Optional |
| cors_allow_origins | Comma-separated list of allowed origins. | Optional |
| cors_expose_headers | Comma-separated list of headers to expose. | Optional |
| cors_max_age | Maximum age for CORS preflight cache. | Optional |
| invoke_mode | BUFFERED or RESPONSE_STREAM. Possible values are: BUFFERED, RESPONSE_STREAM. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.FunctionURLConfig.FunctionUrl | String | The HTTP URL endpoint for your function. |
| AWS.Lambda.FunctionURLConfig.FunctionArn | String | The Amazon Resource Name \(ARN\) of your function. |
| AWS.Lambda.FunctionURLConfig.AuthType | String | The type of authentication that your function URL uses. |
| AWS.Lambda.FunctionURLConfig.Cors.AllowCredentials | Boolean | Whether to allow cookies or other credentials in requests to your function URL. |
| AWS.Lambda.FunctionURLConfig.Cors.AllowHeaders | String | The HTTP headers that origins can include in requests to your function URL. |
| AWS.Lambda.FunctionURLConfig.Cors.AllowMethods | String | The HTTP methods that are allowed when calling your function URL. |
| AWS.Lambda.FunctionURLConfig.Cors.AllowOrigins | String | The origins that can access your function URL. |
| AWS.Lambda.FunctionURLConfig.Cors.ExposeHeaders | String | The HTTP headers in your function response that you want to expose to origins that call your function URL. |
| AWS.Lambda.FunctionURLConfig.Cors.MaxAge | Number | The maximum amount of time, in seconds, that web browsers can cache results of a preflight request. |
| AWS.Lambda.FunctionURLConfig.CreationTime | String | When the function URL was created. |
| AWS.Lambda.FunctionURLConfig.LastModifiedTime | String | When the function URL configuration was last updated. |
| AWS.Lambda.FunctionURLConfig.InvokeMode | String | BUFFERED or RESPONSE_STREAM. |

### aws-kms-key-rotation-enable

***
Enables automatic rotation for a symmetric customer-managed KMS key. Not supported for asymmetric/HMAC keys, keys with imported material, or custom key stores.

#### Base Command

`aws-kms-key-rotation-enable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| key_id | The key ARN to enable rotation for. | Required |
| rotation_period_in_days | Key rotation period in days. Valid range: 90–2560. If omitted when enabling rotation for the first time, the default is 365 days. If rotation is already enabled and this field is not specified, the existing period remains unchanged. | Optional |

#### Context Output

There is no context output for this command.

### aws-elb-load-balancer-attributes-modify

***
Modifies attributes for a Classic Elastic Load Balancer.

#### Base Command

`aws-elb-load-balancer-attributes-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| load_balancer_name | The name of the Load Balancer. | Required |
| access_log_enabled | Whether to enable access logs. (if enabled make sure to provide access_log_s3_bucket_name) Possible values are: true, false. | Optional |
| access_log_s3_bucket_name | S3 bucket name for access logs (required if access_log_enabled=true). | Optional |
| access_log_interval | The interval for publishing the access logs. You can specify an interval of either 5 minutes or 60 minutes. If omitted when enabling logging for the first time, the default is 60 minutes. If logging is already enabled and this field is not specified, the existing period remains unchanged. Possible values are: 5, 60. | Optional |
| access_log_s3_bucket_prefix | S3 key prefix (Path) for access logs.  If the prefix is not provided, the log folder is placed at the root level of the bucket. | Optional |
| connection_draining_enabled | Whether connection draining is enabled for the load balancer. Possible values are: true, false. | Optional |
| connection_draining_timeout | The maximum time, in seconds, to keep the existing connections open before de-registering the instance.  Valid Range: 1 - 3600. | Optional |
| connection_settings_idle_timeout | The load balancer allows the connections to remain idle (no data is sent over the connection) for this specific duration in seconds. Valid Range: 1 - 4000. | Optional |
| cross_zone_load_balancing_enabled | Whether to enable cross-zone load balancing. Possible values are: true, false. | Optional |
| desync_mitigation_mode | Determines how the Classic Load Balancer handles HTTP requests that might pose a security risk to your application. This sets the 'elb.http.desyncmitigationmode' load balancer attribute. Possible values are: monitor, defensive, strictest. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.ELB.LoadBalancer.LoadBalancerName | string | The name of the Classic Load Balancer. |
| AWS.ELB.LoadBalancer.LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled | boolean | Whether cross-zone load balancing is enabled. |
| AWS.ELB.LoadBalancer.LoadBalancerAttributes.ConnectionDraining.Enabled | boolean | Whether connection draining is enabled. |
| AWS.ELB.LoadBalancer.LoadBalancerAttributes.ConnectionDraining.Timeout | number | Connection draining timeout in seconds. |
| AWS.ELB.LoadBalancer.LoadBalancerAttributes.ConnectionSettings.IdleTimeout | number | Idle connection timeout in seconds. |
| AWS.ELB.LoadBalancer.LoadBalancerAttributes.AccessLog.Enabled | boolean | Whether access logs are enabled. |
| AWS.ELB.LoadBalancer.LoadBalancerAttributes.AccessLog.S3BucketName | string | The S3 bucket name for access logs. |
| AWS.ELB.LoadBalancer.LoadBalancerAttributes.AccessLog.EmitInterval | number | Access log publish interval in minutes. |
| AWS.ELB.LoadBalancer.LoadBalancerAttributes.AccessLog.S3BucketPrefix | string | The S3 key prefix for access logs. |
| AWS.ELB.LoadBalancer.LoadBalancerAttributes.AdditionalAttributes | unknown | Additional attributes returned by the API. |

### aws-ec2-vpcs-describe

***
Describes one or more of your VPCs.

#### Base Command

`aws-ec2-vpcs-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;;values=&lt;values&gt;). See AWS documentation for details &amp; filter options (https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html). | Optional |
| vpc_ids | A comma-separated list of VPC IDs. | Optional |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Vpcs.CidrBlock | string | The primary IPv4 CIDR block for the VPC. |
| AWS.EC2.Vpcs.DhcpOptionsId | string | The ID of the set of DHCP options you have associated with the VPC. |
| AWS.EC2.Vpcs.State | string | The current state of the VPC. |
| AWS.EC2.Vpcs.VpcId | string | The ID of the VPC. |
| AWS.EC2.Vpcs.InstanceTenancy | string | The allowed tenancy of instances launched into the VPC. |
| AWS.EC2.Vpcs.IsDefault | string | Indicates whether the VPC is the default VPC. |
| AWS.EC2.Vpcs.Tags.Key | string | The key of the tag. |
| AWS.EC2.Vpcs.Tags.Value | string | The value of the tag. |
| AWS.EC2.Vpcs.Tags.Ipv6CidrBlockAssociationSet.AssociationId | string | The association ID for the IPv6 CIDR block. |
| AWS.EC2.Vpcs.Tags.Ipv6CidrBlockAssociationSet.Ipv6CidrBlock | string | The IPv6 CIDR block. |
| AWS.EC2.Vpcs.Tags.Ipv6CidrBlockAssociationSet.Ipv6CidrBlockState.State | string | The state of the CIDR block. |
| AWS.EC2.Vpcs.Tags.Ipv6CidrBlockAssociationSet.Ipv6CidrBlockState.StatusMessage | string | A message about the status of the CIDR block, if applicable. |
| AWS.EC2.Vpcs.Tags.CidrBlockAssociationSet.AssociationId | string | The association ID for the IPv4 CIDR block. |
| AWS.EC2.Vpcs.Tags.CidrBlockAssociationSet.CidrBlock | string | The IPv4 CIDR block. |
| AWS.EC2.Vpcs.Tags.CidrBlockAssociationSet.CidrBlockState.State | string | The state of the CIDR block. |
| AWS.EC2.Vpcs.Tags.CidrBlockAssociationSet.CidrBlockState.StatusMessage | string | A message about the status of the CIDR block, if applicable. |
| AWS.EC2.Vpcs.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. |

### aws-ec2-subnets-describe

***
Describes one or more of your subnets.

#### Base Command

`aws-ec2-subnets-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;;values=&lt;values&gt;). See AWS documentation for details &amp; filter options (https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html). | Optional |
| subnet_ids | A comma-separated list of subnet IDs. | Optional |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Subnets.AvailabilityZone | string | The Availability Zone of the subnet. |
| AWS.EC2.Subnets.AvailableIpAddressCount | number | The number of unused private IPv4 addresses in the subnet. Note that the IPv4 addresses for any stopped instances are considered unavailable. |
| AWS.EC2.Subnets.CidrBlock | string | The IPv4 CIDR block assigned to the subnet. |
| AWS.EC2.Subnets.DefaultForAz | boolean | Indicates whether this is the default subnet for the Availability Zone. |
| AWS.EC2.Subnets.MapPublicIpOnLaunch | boolean | Indicates whether instances launched in this subnet receive a public IPv4 address. |
| AWS.EC2.Subnets.State | string | The current state of the subnet. |
| AWS.EC2.Subnets.SubnetId | string | The ID of the subnet. |
| AWS.EC2.Subnets.VpcId | string | The ID of the VPC the subnet is in. |
| AWS.EC2.Subnets.AssignIpv6AddressOnCreation | boolean | Indicates whether a network interface created in this subnet \(including a network interface created by RunInstances\) receives an IPv6 address. |
| AWS.EC2.Subnets.Ipv6CidrBlockAssociationSet.AssociationId | string | The association ID for the CIDR block. |
| AWS.EC2.Subnets.Ipv6CidrBlockAssociationSet.Ipv6CidrBlock | string | The IPv6 CIDR block. |
| AWS.EC2.Subnets.Ipv6CidrBlockAssociationSet.Ipv6CidrBlockState.State | string | The state of a CIDR block. |
| AWS.EC2.Subnets.Ipv6CidrBlockAssociationSet.Ipv6CidrBlockState.StatusMessage | string | A message about the status of the CIDR block, if applicable. |
| AWS.EC2.Subnets.Tags.Key | string | The key of the tag. |
| AWS.EC2.Subnets.Tags.Value | string | The value of the tag. |
| AWS.EC2.Subnets.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. |

### aws-ec2-ipam-resource-discoveries-describe

***
Describes IPAM resource discoveries. A resource discovery is an IPAM component that enables IPAM to manage and monitor resources owned by the account.

#### Base Command

`aws-ec2-ipam-resource-discoveries-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipam_resource_discovery_ids | A comma-separated list of the IPAM resource discovery IDs. | Optional |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;;values=&lt;values&gt;). See AWS documentation for details &amp; filter options (https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html). | Optional |
| limit | The maximum number of results to return in a single call. Specify a value between 5 and 1000. Default value is 50. | Optional |
| next_token | The token for the next set of results. | Optional |
| address_region | The Amazon Web Services region for the IP address. | Optional |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.IpamResourceDiscoveries.IpamResourceDiscoveryId | String | The resource discovery ID. |
| AWS.EC2.IpamResourceDiscoveries.OwnerId | String | The ID of the owner. |
| AWS.EC2.IpamResourceDiscoveries.IpamResourceDiscoveryRegion | String | The resource discovery region. |
| AWS.EC2.IpamResourceDiscoveries.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. |

### aws-ec2-ipam-resource-discovery-associations-describe

***
Describes resource discovery association with an Amazon VPC IPAM. An associated resource discovery is a resource discovery that has been associated with an IPAM.

#### Base Command

`aws-ec2-ipam-resource-discovery-associations-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipam_resource_discovery_association_ids | A comma-separated list of the resource discovery association IDs. | Optional |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;;values=&lt;values&gt;). See AWS documentation for details &amp; filter options (https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html). | Optional |
| limit | The maximum number of results to return in a single call. Specify a value between 5 and 1000. Default value is 50. | Optional |
| next_token | The token for the next set of results. | Optional |
| address_region | The Amazon Web Services region for the IP address. | Optional |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.IpamResourceDiscoveryAssociations.IpamResourceDiscoveryAssociationId | String | The resource discovery association ID. |
| AWS.EC2.IpamResourceDiscoveryAssociations.IpamResourceDiscoveryId | String | The resource discovery ID. |
| AWS.EC2.IpamResourceDiscoveryAssociations.IpamRegion | String | The IPAM home region. |
| AWS.EC2.IpamResourceDiscoveryAssociations.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. |

### aws-ec2-latest-ami-get

***
Get The latest AMI.

#### Base Command

`aws-ec2-latest-ami-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region where instances will be created. Must be a valid AWS region identifier. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| executable_users | Scopes the images by users with explicit launch permissions. | Optional |
| filters | One or more filters. Filters must be separated by a semicolon (;) and specified using the format "key=key,values=val". Refer to the AWS documentation for detailed filter options. | Optional |
| owners | Filters the images by the owner. Specify an AWS account ID, self (owner is the sender of the request), or an AWS owner alias (valid values are amazon \| aws-marketplace \| microsoft ). Omitting this option returns all images for which you have launch permissions, regardless of ownership. Separated by ','. | Optional |
| image_ids | The image IDs separated by ','. | Optional |
| include_deprecated | Specifies whether to include deprecaed AMIs. Possible values are: true, false. | Optional |
| include_disabled | Specifies whether to include disabled AMIs. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Images.Architecture | string | The architecture of the image. |
| AWS.EC2.Images.CreationDate | date | The date and time the image was created. |
| AWS.EC2.Images.ImageId | string | The ID of the AMI. |
| AWS.EC2.Images.ImageLocation | string | The location of the AMI. |
| AWS.EC2.Images.ImageType | string | The type of image. |
| AWS.EC2.Images.Public | boolean | Indicates whether the image has public launch permissions. The value is true if this image has public launch permissions or false if it has only implicit and explicit launch permissions. |
| AWS.EC2.Images.KernelId | string | The kernel associated with the image, if any. Only applicable for machine images. |
| AWS.EC2.Images.OwnerId | string | The AWS account ID of the image owner. |
| AWS.EC2.Images.Platform | string | The value is Windows for Windows AMIs; otherwise blank. |
| AWS.EC2.Images.ProductCodes.ProductCodeId | string | The product code. |
| AWS.EC2.Images.ProductCodes.ProductCodeType | string | The type of product code. |
| AWS.EC2.Images.RamdiskId | string | The RAM disk associated with the image, if any. Only applicable for machine images. |
| AWS.EC2.Images.State | string | The current state of the AMI. If the state is available , the image is successfully registered and can be used to launch an instance. |
| AWS.EC2.Images.BlockDeviceMappings.DeviceName | string | The device name \(for example, /dev/sdh or xvdh \). |
| AWS.EC2.Images.BlockDeviceMappings.VirtualName | string | The virtual device name \(ephemeral N\). |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.Encrypted | boolean | Indicates whether the EBS volume is encrypted. |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.DeleteOnTermination | boolean | Indicates whether the EBS volume is deleted on instance termination. |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.Iops | number | The number of I/O operations per second \(IOPS\) that the volume supports. |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.KmsKeyId | string | Identifier \(key ID, key alias, ID ARN, or alias ARN\) for a user-managed CMK under which the EBS volume is encrypted. |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.SnapshotId | string | The ID of the snapshot. |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.VolumeSize | number | The size of the volume, in GiB. |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.VolumeType | string | The volume type. |
| AWS.EC2.Images.BlockDeviceMappings.NoDevice | string | Suppresses the specified device included in the block device mapping of the AMI. |
| AWS.EC2.Images.Description | string | The description of the AMI that was provided during image creation. |
| AWS.EC2.Images.EnaSupport | boolean | Specifies whether enhanced networking with ENA is enabled. |
| AWS.EC2.Images.Hypervisor | string | The hypervisor type of the image. |
| AWS.EC2.Images.ImageOwnerAlias | string | The AWS account alias \(for example, amazon , self \) or the AWS account ID of the AMI owner. |
| AWS.EC2.Images.Name | string | The name of the AMI that was provided during image creation. |
| AWS.EC2.Images.RootDeviceName | string | The device name of the root device volume \(for example, /dev/sda1\). |
| AWS.EC2.Images.RootDeviceType | string | The type of root device used by the AMI. The AMI can use an EBS volume or an instance store volume. |
| AWS.EC2.Images.SriovNetSupport | string | Specifies whether enhanced networking with the Intel 82599 Virtual Function interface is enabled. |
| AWS.EC2.Images.StateReason.Code | string | The reason code for the state change. |
| AWS.EC2.Images.StateReason.Message | string | The message for the state change. |
| AWS.EC2.Images.Tags.Key | string | The key of the tag. |
| AWS.EC2.Images.Tags.Value | string | The value of the tag. |
| AWS.EC2.Images.VirtualizationType | string | The type of virtualization of the AMI. |
| AWS.EC2.Images.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. |

### aws-ec2-network-acl-create

***
Creates a network ACL in a VPC. Network ACLs provide an optional layer of security (in addition to security groups) for the instances in your VPC.

#### Base Command

`aws-ec2-network-acl-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| vpc_id | The ID of the VPC. | Required |
| client_token | Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. | Optional |
| tag_specifications | The tags to assign to the network ACL. Must be separated by a semicolon (;) and specified using the format "key=key,values=val". | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.VpcId.NetworkAcl.Associations.NetworkAclAssociationId | String | The ID of the association between a network ACL and a subnet. |
| AWS.EC2.VpcId.NetworkAcl.Associations.NetworkAclId | String | The ID of the network ACL. |
| AWS.EC2.VpcId.NetworkAcl.Associations.SubnetId | String | The ID of the subnet. |
| AWS.EC2.VpcId.NetworkAcl.Entries.CidrBlock | String | The IPv4 network range to allow or deny, in CIDR notation. |
| AWS.EC2.VpcId.NetworkAcl.Entries.Egress | Boolean | Indicates whether the rule is an egress rule \(applied to traffic leaving the subnet\). |
| AWS.EC2.VpcId.NetworkAcl.Entries.IcmpTypeCode.Code | Number | The ICMP code. A value of -1 means all codes for the specified ICMP type. |
| AWS.EC2.VpcId.NetworkAcl.Entries.IcmpTypeCode.Type | Number | The ICMP type. A value of -1 means all types. |
| AWS.EC2.VpcId.NetworkAcl.Entries.Ipv6CidrBlock | String | The IPv6 network range to allow or deny, in CIDR notation. |
| AWS.EC2.VpcId.NetworkAcl.Entries.PortRange.From | Number | The first port in the range. |
| AWS.EC2.VpcId.NetworkAcl.Entries.PortRange.To | Number | The last port in the range. |
| AWS.EC2.VpcId.NetworkAcl.Entries.Protocol | String | The protocol number. A value of "-1" means all protocols. |
| AWS.EC2.VpcId.NetworkAcl.Entries.RuleAction | String | Indicates whether to allow or deny the traffic that matches the rule. |
| AWS.EC2.VpcId.NetworkAcl.Entries.RuleNumber | Number | The rule number for the entry. ACL entries are processed in ascending order by rule number. |
| AWS.EC2.VpcId.NetworkAcl.NetworkAclId | String | The ID of the network ACL. |
| AWS.EC2.VpcId.NetworkAcl.Tags.Key | String | The key of the tag. |
| AWS.EC2.VpcId.NetworkAcl.Tags.Value | String | The value of the tag. |
| AWS.EC2.VpcId.NetworkAcl.VpcId | String | The ID of the VPC for the network ACL. |
| AWS.EC2.VpcId.NetworkAcl.OwnerId | String | The ID of the AWS account that owns the network ACL. |
| AWS.EC2.VpcId.NetworkAcl.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. |

### aws-ec2-ipam-discovered-public-addresses-get

***
Gets the public IP addresses that have been discovered by IPAM.

#### Base Command

`aws-ec2-ipam-discovered-public-addresses-get`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                            | **Required** |
| --- |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| account_id | The AWS account ID.                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| ipam_resource_discovery_id | An IPAM resource discovery ID.                                                                                                                                                                                                                                                                                                                                                                                                                                             | Required |
| address_region | The Amazon Web Services region for the IP address.                                                                                                                                                                                                                                                                                                                                                                                                                         | Required |
| filters | One or more filters. Filters must be separated by a semicolon (;) and specified using the format "key=key,values=val". Refer to the AWS documentation for detailed filter options.                                                                                                                                                                                                                                                                                         | Optional |
| limit | The maximum number of results to return in a single call. Specify a value between 1000 and 5000.                                                                                                                                                                                                                                                                                                                                                                           | Optional |
| next_token | The token for the next set of results.                                                                                                                                                                                                                                                                                                                                                                                                                                     | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.IpamDiscoveredPublicAddresses.Address | String | IPAM discovered public addresses. |
| AWS.EC2.IpamDiscoveredPublicAddresses.AddressOwnerId | String | The ID of the owner of the resource the IP address is assigned to. |
| AWS.EC2.IpamDiscoveredPublicAddresses.AddressType | String | The IP address type. |
| AWS.EC2.IpamDiscoveredPublicAddresses.AssociationStatus | String | The association status. |
| AWS.EC2.IpamDiscoveredPublicAddresses.InstanceId | String | The instance ID of the instance the assigned IP address is assigned to. |
| AWS.EC2.IpamDiscoveredPublicAddresses.Tags | Unknown | Tags associated with the IP address. |
| AWS.EC2.IpamDiscoveredPublicAddresses.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. |

### aws-ec2-tags-create

***
Adds or overwrites one or more tags for the specified Amazon EC2 resource or resources. When you specify an existing tag key, the value is overwritten with the new value.

#### Base Command

`aws-ec2-tags-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| resources | The IDs of one or more resources to tag, separated by a comma. For example, ami-1a2b3c4d. | Required |
| tags | One or more tags. Must be separated by a semicolon (;) and specified using the format "key=abc,value=123;key=fed,value=456". | Required |

#### Context Output

There is no context output for this command.

### aws-s3-bucket-website-get

***
Returns the website configuration for a bucket.

#### Base Command

`aws-s3-bucket-website-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| bucket | The bucket name for which to get the website configuration. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3-Buckets.BucketWebsite.ErrorDocument | Object | The object key name of the website error document to use for 4XX class errors. |
| AWS.S3-Buckets.BucketWebsite.IndexDocument | Object | The name of the index document for the website \(for example index.html\). |
| AWS.S3-Buckets.BucketWebsite.RedirectAllRequestsTo | Object | Specifies the redirect behavior of all requests to a website endpoint of an Amazon S3 bucket. |
| AWS.S3-Buckets.BucketWebsite.RoutingRules | Array | Rules that define when a redirect is applied and the redirect behavior. |

### aws-s3-bucket-acl-get

***
Return the access control list (ACL) of a bucket.

#### Base Command

`aws-s3-bucket-acl-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| bucket | Specifies the S3 bucket whose ACL is being requested. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3-Buckets.BucketAcl.Grants | Array | A list of grants. |
| AWS.S3-Buckets.BucketAcl.Owner | Object | Container for the bucket owner's display name and ID. |

### aws-acm-certificate-options-update

***
Updates Certificate Transparency (CT) logging for an AWS Certificate Manager (ACM) certificate (ENABLED or DISABLED).

#### Base Command

`aws-acm-certificate-options-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| certificate_arn | The ARN of the ACM certificate to update. | Required |
| transparency_logging_preference | Whether the certificate is recorded in public CT logs. Possible values are: ENABLED, DISABLED. | Required |

#### Context Output

There is no context outputs for this command.

### aws-ec2-security-group-create

***
Creates a security group.

#### Base Command

`aws-ec2-security-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| group_name | The name of the security group. Up to 255 characters in length. Cannot start with sg-. Names are case-insensitive and must be unique within the VPC. | Required |
| description | A description for the security group. This is informational only. Up to 255 characters in length. Valid characters: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}!$*. | Required |
| vpc_id | The ID of the VPC. Required for a nondefault VPC. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-security-group-delete

***
Deletes a security group.

#### Base Command

`aws-ec2-security-group-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| group_id | The ID of the security group to delete (e.g., sg-12345678). Required if group_name is not provided. | Optional |
| group_name | The name of the security group to delete. Required if group_id is not provided. Note that you can’t reference a security group for EC2-VPC by name. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-security-groups-describe

***
Describes the specified security groups or all of your security groups. Returns detailed information about security groups including their rules, tags, and associated VPC information.

#### Base Command

`aws-ec2-security-groups-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| group_ids | Comma-separated list of security group IDs (e.g., sg-12345678,sg-87654321). | Optional |
| group_names | Comma-separated list of security group names. group_names is only supported for EC2-Classic and default VPC. | Optional |
| filters | One or more custom filters to apply, separated by ';' (for example, name=&lt;name&gt;;values=&lt;values&gt;).You can specify up to 50 filters and up to 200 values per filter in a single request. | Optional |
| limit | The maximum number of records to return. Valid range is 5-1000. Default is 50. | Optional |
| next_token | The nextToken value returned from a previous paginated request, where maxResults was used and the results exceeded the value of that parameter. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.SecurityGroupsNextToken | string | The nextToken value returned from a previous paginated request, where maxResults was used and the results exceeded the value of that parameter. |
| AWS.EC2.SecurityGroups.Description | string | A description of the security group. |
| AWS.EC2.SecurityGroups.GroupName | string | The name of the security group. |
| AWS.EC2.SecurityGroups.IpPermissions | unknown | The inbound rules associated with the security group. |
| AWS.EC2.SecurityGroups.OwnerId | string | The AWS account ID of the owner of the security group. |
| AWS.EC2.SecurityGroups.GroupId | string | The ID of the security group. |
| AWS.EC2.SecurityGroups.IpPermissionsEgress | array | The outbound rules associated with the security group. |
| AWS.EC2.SecurityGroups.VpcId | string | The ID of the VPC for the security group. |
| AWS.EC2.SecurityGroups.Tags.Key | string | The key of the tag. |
| AWS.EC2.SecurityGroups.Tags.Value | string | The value of the tag. |
| AWS.EC2.SecurityGroups.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. |
| AWS.EC2.SecurityGroups.SecurityGroupArn | string | The ARN of the security group. |

### aws-ec2-security-group-egress-authorize

***
Adds the specified inbound (egress) rules to a security group.

#### Base Command

`aws-ec2-security-group-egress-authorize`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| group_id | The ID of the security group. | Required |
| protocol | The IP protocol: tcp, udp, icmp, or icmpv6 or a number. Use -1 to specify all protocols. Use with from_port, to_port and CIDR arguments for simple rule authorization. VPC security group rules must specify protocols explicitly. | Optional |
| from_port | If the protocol is TCP or UDP, this is the start of the port range. If the protocol is ICMP or ICMPv6, this is the ICMP type or -1 (all ICMP types). | Optional |
| to_port | If the protocol is TCP or UDP, this is the end of the port range. If the protocol is ICMP or ICMPv6, this is the ICMP code or -1 (all ICMP codes). If the start port is -1 (all ICMP types), then the end port must be -1 (all ICMP codes). | Optional |
| cidr | The IPv4 address range in CIDR format (e.g., "0.0.0.0/0"). Use with protocol and from_port, to_port arguments for simple rule authorization. | Optional |
| ip_permissions | The sets of IP permissions to authorize, in JSON format. Use this for complex rule configurations or when authorizing multiple rules. Cannot be used together with protocol/port/CIDR arguments. | Optional |

#### Context Output

There is no context output for this command.
