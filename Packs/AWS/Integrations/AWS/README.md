Support for AWS cloud
This integration was integrated and tested with version 1.0.0 of AWS.

## Configure AWS in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Main Role | Main Role to be used for authentication e.g. 'PowerUserAccess' | False |
| Default AWS Account ID | AWS Account ID used for running integration test |  |
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
Create or Update AWS account password policy.

#### Base Command

`aws-iam-account-password-policy-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| minimum_password_length | The minimum number of characters allowed in an IAM user password. | Optional |
| require_symbols | Whether IAM user passwords must contain at least one of the non-alphanumeric characters. Possible values are: true, false. | Optional |
| require_numbers | Whether IAM user passwords must contain at least one numeric character (0 to 9). Possible values are: true, false. | Optional |
| require_uppercase_characters | Whether IAM user passwords must contain at least one uppercase character from the ISO basic Latin alphabet (A to Z). Can be "True" or "False". Possible values are: true, false. | Optional |
| require_lowercase_characters | Whether IAM user passwords must contain at least one lowercase character from the ISO basic Latin alphabet (a to z). Can be "True" or "False". Possible values are: true, false. | Optional |
| allow_users_to_change_password | Allows all IAM users in your account to use the AWS Management Console to change their own passwords. Can be "True" or "False". Possible values are: true, false. | Optional |
| max_password_age | The number of days that an IAM user password is valid. | Optional |
| password_reuse_prevention | The number of previous passwords that IAM users are prevented from reusing. | Optional |
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

### aws-eks-access-entry-update

***
Updates an existing Access Entry for an Amazon EKS cluster. Required IAM Permission: eks:UpdateAccessEntry.

#### Base Command

`aws-eks-access-entry-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| cluster_name | The name of the cluster for which to update the AccessEntry. | Required |
| principal_arn | ARN of the IAM principal for the AccessEntry. | Required |
| kubernetes_groups | A comma-separated list of names for Kubernetes groups in RoleBindings or ClusterRoleBindings. | Optional |
| client_request_token | Unique identifier for idempotency. | Optional |
| user_name | Username for Kubernetes authentication. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EKS.AccessEntry.clusterName | String | The name of the cluster. |
| AWS.EKS.AccessEntry.principalArn | String | The ARN of the IAM principal for the access entry. |
| AWS.EKS.AccessEntry.username | String | The Kubernetes user name for the access entry. |
| AWS.EKS.AccessEntry.type | String | The type of the access entry. |
| AWS.EKS.AccessEntry.createdAt | String | The date and time the access entry was created. |
| AWS.EKS.AccessEntry.modifiedAt | String | The date and time the access entry was last modified. |
| AWS.EKS.AccessEntry.kubernetesGroups | Array | The Kubernetes groups that the access entry is associated with. |
| AWS.EKS.AccessEntry.tags | Object | Metadata tags associated with the access entry. |
| AWS.EKS.AccessEntry.accessEntryArn | String | The ARN of the access entry. |

#### Command Example

```!aws-eks-access-entry-update account_id=account-id region=region cluster_name=cluster_name principal_arn=arn:aws:iam::123456789012:role/test-role user_name=my-k8s-user```

### aws-eks-access-entry-create

***
Creates a new Access Entry for an Amazon EKS cluster. Required IAM Permission: eks:CreateAccessEntry.

#### Base Command

`aws-eks-access-entry-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| cluster_name | The name of the cluster for which to create an access entry. | Required |
| principal_arn | ARN of the IAM principal for the AccessEntry. | Required |
| kubernetes_groups | A comma-separated list of names for Kubernetes groups in RoleBindings or ClusterRoleBindings. | Optional |
| tags | A JSON string containing metadata tags for categorization and organization. Each tag consists of a key and an optional value. For example, '{"Environment": "prod", "Team": "platform"}'. | Optional |
| client_request_token | Unique identifier for idempotency. | Optional |
| type | The type of access entry to create. Default is Standard. Possible values are: Standard, FARGATE_LINUX, EC2_LINUX, EC2_WINDOWS. | Optional |
| user_name | Username for Kubernetes authentication. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EKS.AccessEntry.clusterName | String | The name of the cluster. |
| AWS.EKS.AccessEntry.principalArn | String | The ARN of the IAM principal for the access entry. |
| AWS.EKS.AccessEntry.username | String | The Kubernetes user name for the access entry. |
| AWS.EKS.AccessEntry.type | String | The type of the access entry. |
| AWS.EKS.AccessEntry.createdAt | String | The date and time the access entry was created. |
| AWS.EKS.AccessEntry.modifiedAt | String | The date and time the access entry was last modified. |
| AWS.EKS.AccessEntry.kubernetesGroups | Array | The Kubernetes groups that the access entry is associated with. |
| AWS.EKS.AccessEntry.tags | Object | Metadata tags associated with the access entry. |
| AWS.EKS.AccessEntry.accessEntryArn | String | The ARN of the access entry. |

#### Command Example

```!aws-eks-access-entry-create account_id=account-id region=region cluster_name=cluster_name principal_arn=arn:aws:iam::123456789012:role/test-role```

### aws-eks-clusters-list

***
Returns a list of EKS clusters. Required IAM Permission: eks:ListClusters.

#### Base Command

`aws-eks-clusters-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| limit | The maximum number of clusters returned in response. The possible values are between 1 and 100. Default is 50. | Optional |
| next_token | The nextToken value returned from a previous paginated ListClusters request. Use the value from AWS.EKS.ClustersNextToken. | Optional |
| include | Indicates whether external clusters are included in the returned list. Set to 'all' to include connected clusters. Supports comma-separated values. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EKS.Clusters | String | A list of all of the clusters for your account in the specified Region. |
| AWS.EKS.ClustersNextToken | String | The nextToken value to include in a future ListClusters request. When the results of a ListClusters request exceed maxResults, you can use this value to retrieve the next page of results. |

#### Command Example

```!aws-eks-clusters-list account_id=account_id region=region```

### aws-rds-db-instance-modify

***
Modifies an existing Amazon RDS DB instance. Allows updating various settings, including the instance class, storage capacity, security groups, and other configuration parameters, without the need to create a new instance.

#### Base Command

`aws-rds-db-instance-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| db_instance_identifier | The identifier of DB instance to modify. This value is stored as a lowercase string. | Required |
| publicly_accessible | Wether the DB instance is publicly accessible. Possible values are: true, false. | Optional |
| apply_immediately | Wether the modifications in this request and any pending modifications are asynchronously applied as soon as possible, regardless of the PreferredMaintenanceWindow setting for the DB instance. By default, this parameter is disabled. If this parameter is disabled, changes to the DB instance are applied during the next maintenance window. Some parameter changes can cause an outage and are applied on the next call to RebootDBInstance , or the next failure reboot. Possible values are: true, false. | Optional |
| copy_tags_to_snapshot | Wether to copy all tags from the DB instance to snapshots of the DB instance. By default, tags aren’t copied. Possible values are: true, false. | Optional |
| backup_retention_period | The number of days to retain automated backups. Setting this parameter to a positive number enables backups. Setting this parameter to 0 disables automated backups. | Optional |
| enable_iam_database_authentication | Wether to enable mapping of Amazon Web Services Identity and Access Management (IAM) accounts to database accounts. By default, mapping isn’t enabled. Possible values are: true, false. | Optional |
| deletion_protection | Wether the DB instance has deletion protection enabled. The database can’t be deleted when deletion protection is enabled. By default, deletion protection isn’t enabled. For more information, see Deleting a DB Instance. Possible values are: true, false. | Optional |
| auto_minor_version_upgrade | Specifies whether minor version upgrades are applied automatically to the DB instance during the maintenance window. Behavior: An outage occurs only if automatic upgrades are enabled for the maintenance window, a newer minor version is available, and RDS has enabled automatic patching for the engine version; otherwise, changes are applied as soon as possible without causing an outage. Note: Do not enable for RDS Custom DB instances (operation will fail). Possible values are: true, false. | Optional |
| multi_az | Behavior: Specifies whether the DB instance is a Multi-AZ deployment. Changing this parameter does not cause an outage and is applied during the next maintenance window unless ApplyImmediately is enabled. Not applicable to RDS Custom DB instances. Possible values are: true, false. | Optional |
| vpc_security_group_ids | A list of Amazon EC2 VPC security groups to associate with this DB instance. This setting doesn’t apply to the following DB instances: Amazon Aurora, RDS Custom. | Optional |

#### Context Output

There is no context output for this command.

### aws-cloudtrail-trail-update

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
| include_global_service_events | Whether the trail is publishing events from global services such as IAM to the log files. Possible values are: true, false. | Optional |
| is_multi_region_trail | Whether the trail applies only to the current region or to all regions. The default is false. If the trail exists only in the current region and this value is set to true, shadow trails (replications of the trail) will be created in the other regions. If the trail exists in all regions and this value is set to false, the trail will remain in the region where it was created, and its shadow trails in other regions will be deleted. Possible values are: true, false. | Optional |
| enable_log_file_validation | Whether log file validation is enabled. The default is false. Possible values are: true, false. | Optional |
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
| AWS.CloudTrail.Trail.IsMultiRegionTrail | boolean | Whether the trail exists only in one region or exists in all regions. |
| AWS.CloudTrail.Trail.HomeRegion | string | The region in which the trail was created. |
| AWS.CloudTrail.Trail.LogFileValidationEnabled | boolean | Whether log file validation is enabled. |
| AWS.CloudTrail.Trail.CloudWatchLogsLogGroupArn | string | Amazon Resource Name \(ARN\), a unique identifier that represents the log group to which CloudTrail logs will be delivered. |
| AWS.CloudTrail.Trail.CloudWatchLogsRoleArn | string | The role for the CloudWatch Logs endpoint to assume to write to a user's log group. |
| AWS.CloudTrail.Trail.KMSKeyId | string | The KMS key ID that encrypts the logs delivered by CloudTrail. |
| AWS.CloudTrail.Trail.HasCustomEventSelectors | boolean | Specifies if the trail has custom event selectors. |
| AWS.CloudTrail.Trail.HasInsightSelectors | boolean | Whether a trail has insight selectors enabled. |
| AWS.CloudTrail.Trail.IsOrganizationTrail | boolean | Whether the trail is an organization trail. |

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
| db_cluster_identifier | The DB cluster identifier for the modified cluster. This parameter is not case sensitive and is valid for Aurora DB and Multi-AZ DB cluster types. It must match the identifier of an existing DB cluster. | Required |
| deletion_protection | Whether the DB cluster has deletion protection enabled. The database can’t be deleted when deletion protection is enabled. By default, deletion protection isn’t enabled. Possible values are: true, false. | Optional |
| enable_iam_database_authentication | Whether to enable mapping of Amazon Web Services Identity and Access Management (IAM) accounts to database accounts. By default, mapping isn’t enabled. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.
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
| mfa_delete | Whether MFA delete is enabled in the bucket versioning configuration. This element is only returned if the bucket has been configured with MFA delete. If the bucket has never been so configured, this element is not returned. | Optional |
| status | The versioning state of the bucket. Possible values are: Enabled, Suspended. | Required |

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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| bucket | The name of the Amazon S3 bucket from which to delete the bucket policy. | Required |

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
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. The default value is us-east-1.| Required |
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
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
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
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
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
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| limit | The maximum number of results to return in a single call. Specify a value between 5 and 1000. Default value is 50. Default is 50. | Optional |
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
| AWS.EC2.IpamResourceDiscoveries.AccountId | string | The ID of the AWS account associated with the EC2 instance. This key is only present when the parameter "AWS organization accounts" is provided. |

### aws-ec2-ipam-resource-discovery-associations-describe

***
Describes resource discovery association with an Amazon VPC IPAM. An associated resource discovery is a resource discovery that has been associated with an IPAM.

#### Base Command

`aws-ec2-ipam-resource-discovery-associations-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipam_resource_discovery_association_ids | A comma-separated list of the resource discovery association IDs. | Optional |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| limit | The maximum number of results to return in a single call. Specify a value between 5 and 1000. Default value is 50. Default is 50. | Optional |
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
| AWS.EC2.IpamResourceDiscoveryAssociations.AccountId | string | The ID of the AWS account associated with the EC2 instance. This key is only present when the parameter "AWS organization accounts" is provided. |

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

### aws-ssm-inventory-entries-list

***
Returns a list of inventory items.

#### Base Command

`aws-ssm-inventory-entries-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_id | The managed node ID for which you want inventory information. | Required |
| type_name | The type of inventory item for which you want information. | Required |
| limit | The maximum number of items to return for this call. The maximum value is 50. Default is 50. | Optional |
| filters | One or more filters separated by ';' (for example, key=&lt;key&gt;,values=&lt;values&gt;,type=&lt;type&gt;;key=&lt;key&gt;,values=&lt;values&gt;,type=&lt;type&gt;). Use a filter to return a more specific list of results. The value of type can be from the following closed list: Equal, NotEqual, BeginWith, LessThan, GreaterThan, Exists. | Optional |
| next_token | The token for the next set of items to return. Use AWS.SSM.Inventory.EntriesNextPageToken. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SSM.Inventory.TypeName | string | The type of inventory item returned by the request. |
| AWS.SSM.Inventory.InstanceId | string | The managed node ID targeted by the request to query inventory information. |
| AWS.SSM.Inventory.SchemaVersion | string | The inventory schema version used by the managed nodes. |
| AWS.SSM.Inventory.CaptureTime | string | The time that inventory information was collected for the managed nodes. |
| AWS.SSM.Inventory.Entries | object | A list of inventory items on the managed nodes. |
| AWS.SSM.Inventory.EntriesNextPageToken | object | The token to use when requesting the next set of items. |

### aws-s3-buckets-list

***
Returns a list of all buckets owned by the authenticated sender of the request.

#### Base Command

`aws-s3-buckets-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| limit | Maximum number of buckets to be returned in response. The maximum value is 10000. Default is 50. | Optional |
| next_token | The token for the next set of items to return. Use value from AWS.S3.BucketsNextPageToken. | Optional |
| prefix | Limits the response to bucket names that begin with the specified bucket name prefix. | Optional |
| filter_by_region | A comma-separated list of regions that limits the response to buckets that are located in the specified Amazon Web Services Region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3.Buckets.BucketName | string | The name of the bucket. |
| AWS.S3.Buckets.CreationDate | string | Date the bucket was created. This date can change when making changes to your bucket, such as editing its bucket policy. |
| AWS.S3.Buckets.BucketRegion | string | BucketRegion indicates the Amazon Web Services region where the bucket is located. |
| AWS.S3.Buckets.BucketArn | string | The Amazon Resource Name \(ARN\) of the S3 bucket. |
| AWS.S3.BucketsOwner.DisplayName | string | Container for the display name of the owner. |
| AWS.S3.BucketsOwner.ID | string | Container for the ID of the owner. |
| AWS.S3.BucketsNextPageToken | string | BucketsNextPageToken is included in the response when there are more buckets that can be listed with pagination. The next ListBuckets request to Amazon S3 can be continued with this BucketsNextPageToken. |
| AWS.S3.BucketsPrefix | string | If Prefix was sent with the request, it is included in the response. |

### aws-ssm-command-run

***
Runs commands on one or more managed nodes.

#### Base Command

`aws-ssm-command-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_ids | A comma-separated list of IDs of the managed nodes where the command should run. Maximum of 50 IDs. | Optional |
| targets | One or more targets separated by ';' (for example, key=&lt;key1&gt;,values=&lt;value1&gt;,&lt;value2&gt;;key=&lt;key2&gt;,values=&lt;value3&gt;,&lt;value4&gt;). An array of search criteria used to target managed nodes, where each criterion consists of a Key and a Value that you specify. | Optional |
| document_name | The name of the Amazon Web Services Systems Manager document (SSM document) to run. This can be a public document or a custom document. To run a shared document belonging to another account, specify the document Amazon Resource Name (ARN). | Required |
| document_version | The SSM document version to use in the request. You can specify $DEFAULT, $LATEST, or a specific version number. | Optional |
| document_hash | The Sha256 hash created by the system when the document was created. | Optional |
| command_timeout | If this time (in seconds) is reached and the command hasn’t already started running, it won’t run. Minimum value of 30. Maximum value of 2592000. | Optional |
| comment | User-specified information about the command, such as a brief description of what the command should do. | Optional |
| parameters | The required and optional parameters specified in the document being run. The template is 'key=&lt;key1&gt;,values=&lt;value&gt;,&lt;value&gt;;key=&lt;key2&gt;,values=&lt;value&gt;,&lt;value&gt;'. | Optional |
| output_s3_bucket_name | The name of the S3 bucket where command execution responses should be stored. | Optional |
| output_s3_key_prefix | The directory structure within the S3 bucket where the responses should be stored. | Optional |
| max_concurrency | The maximum number of managed nodes that are allowed to run the command at the same time. You can specify a number such as 10 or a percentage such as 10%. Default is 50. | Optional |
| max_errors | The maximum number of errors allowed without the command failing. When the command fails one more time beyond the value of MaxErrors, the systems stops sending the command to additional targets. You can specify a number like 10 or a percentage like 10%. Default is 0. | Optional |
| polling_timeout | The timeout in seconds until polling ends. Default is 600. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SSM.Command.CommandId | String | A unique identifier for this command. |
| AWS.SSM.Command.DocumentName | String | The name of the document requested for execution. |
| AWS.SSM.Command.DocumentVersion | String | The Systems Manager document \(SSM document\) version. |
| AWS.SSM.Command.Comment | String | User-specified information about the command, such as a brief description of what the command should do. |
| AWS.SSM.Command.ExpiresAfter | String | If a command expires, it changes status to DeliveryTimedOut for all invocations that have the status InProgress, Pending, or Delayed. ExpiresAfter is calculated based on the total timeout for the overall command. |
| AWS.SSM.Command.Parameters | Object | The parameter values to be inserted in the document when running the command. |
| AWS.SSM.Command.InstanceIds | Object | The managed node IDs against which this command was requested. |
| AWS.SSM.Command.Targets | Object | An array of search criteria used to target managed nodes, where each criterion consists of a Key and a Value that you specify. |
| AWS.SSM.Command.RequestedDateTime | String | The date and time the command was requested. |
| AWS.SSM.Command.Status | String | The status of the command. |
| AWS.SSM.Command.StatusDetails | String | A detailed status of the command execution. StatusDetails includes more information than Status because it includes states resulting from error and concurrency control parameters. |
| AWS.SSM.Command.OutputS3BucketName | String | The name of the S3 bucket where command execution responses should be stored. |
| AWS.SSM.Command.OutputS3KeyPrefix | String | The directory structure within the S3 bucket where the responses should be stored. |
| AWS.SSM.Command.MaxConcurrency | String | The maximum number of managed nodes that are allowed to run the command at the same time. |
| AWS.SSM.Command.MaxErrors | String | The maximum number of errors allowed before the system stops sending the command to additional targets. |
| AWS.SSM.Command.TargetCount | Number | The number of targets for the command. |
| AWS.SSM.Command.CompletedCount | Number | The number of targets for which the command invocation reached a terminal state. Terminal states include the following: Success, Failed, Execution Timed Out, Delivery Timed Out, Cancelled, Terminated, or Undeliverable. |
| AWS.SSM.Command.ErrorCount | Number | The number of targets for which the status is Failed or Execution Timed Out. |
| AWS.SSM.Command.DeliveryTimedOutCount | Number | The number of targets for which the status is Delivery Timed Out. |
| AWS.SSM.Command.ServiceRole | String | The Identity and Access Management \(IAM\) service role that Run Command, a tool in Amazon Web Services Systems Manager, uses to act on your behalf when sending notifications about command status changes. |
| AWS.SSM.Command.NotificationConfig.NotificationArn | String | An Amazon Resource Name \(ARN\) for an Amazon Simple Notification Service \(Amazon SNS\) topic. Run Command pushes notifications about command status changes to this topic. |
| AWS.SSM.Command.NotificationConfig.NotificationEvents | Object | The different events for which you can receive notifications. |
| AWS.SSM.Command.NotificationConfig.NotificationType | String | The type of notification. |
| AWS.SSM.Command.CloudWatchOutputConfig.CloudWatchLogGroupName | String | The name of the CloudWatch Logs log group where you want to send command output. |
| AWS.SSM.Command.CloudWatchOutputConfig.CloudWatchOutputEnabled | Boolean | Enables Systems Manager to send command output to CloudWatch Logs. |
| AWS.SSM.Command.TimeoutSeconds | Number | The TimeoutSeconds value specified for a command. |
| AWS.SSM.Command.AlarmConfiguration.IgnorePollAlarmFailure | String | When this value is true, your automation or command continues to run in cases where we can’t retrieve alarm status information from CloudWatch. In cases where we successfully retrieve an alarm status of OK or INSUFFICIENT_DATA, the automation or command continues to run, regardless of this value. |
| AWS.SSM.Command.AlarmConfiguration.Alarms.Name | String | The name of your CloudWatch alarm. |
| AWS.SSM.Command.TriggeredAlarms.Name | String | The name of your CloudWatch alarm. |
| AWS.SSM.Command.TriggeredAlarms.State | String | The state of your CloudWatch alarm. |

### aws-ec2-regions-describe

***
Describes the Regions that are enabled for your account, or all Regions.

#### Base Command

`aws-ec2-regions-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| region_names | The names of the Regions. You can specify any Regions, whether they are enabled and disabled for your account. | Optional |
| all_regions | Indicates whether to display all Regions, including Regions that are disabled for your account. Possible values are: true, false. | Optional |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). A filter name and value pair that is used to return a more specific list of results from a describe operation. Filters can be used to match a set of resources by specific criteria, such as tags, attributes, or IDs. Possible filters are endpoint, opt-in-status, region-name. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Regions.Endpoint | string | The region service endpoint. |
| AWS.EC2.Regions.RegionName | string | The name of the region. |
| AWS.EC2.Regions.OptInStatus | string | The Region opt-in status. The possible values are opt-in-not-required, opted-in, and not-opted-in. |

### aws-s3-bucket-create

***
Creates a new S3 bucket.

#### Base Command

`aws-s3-bucket-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| bucket_name | The name of the bucket to create. For more information about bucket naming rules see https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html. | Required |
| acl | The canned ACL to apply to the bucket. Possible values are: private, public-read, public-read-write, authenticated-read. | Optional |
| location_constraint | Specifies the Region where the bucket will be created. You might choose a Region to optimize latency, minimize costs, or address regulatory requirements. The default is the account region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Optional |
| grant_full_control | Allows grantee the read, write, read ACP, and write ACP permissions on the bucket. | Optional |
| grant_read | Allows grantee to list the objects in the bucket. | Optional |
| grant_read_acp | Allows grantee to read the bucket ACL. | Optional |
| grant_write | Allows grantee to create new objects in the bucket. | Optional |
| grant_write_acp | Allows grantee to write the ACL for the applicable bucket. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3.Buckets.BucketName | string | The name of the bucket that was created. |
| AWS.S3.Buckets.Location | string | The AWS Region the bucket was created. |
| AWS.S3.Buckets.BucketArn | string | The Amazon Resource Name \(ARN\) of the S3 bucket. |

### aws-ec2-network-interface-attribute-modify

***
Modifies the specified network interface attribute. You can specify only one attribute at a time. You can use this action to attach and detach security groups from an existing EC2 instance.

#### Base Command

`aws-ec2-network-interface-attribute-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| network_interface_id | The ID of the network interface. | Required |
| ena_srd_enabled | Indicates whether ENA Express is enabled for the network interface. Possible values are: true, false. | Optional |
| ena_srd_udp_enabled | Indicates whether UDP traffic to and from the instance uses ENA Express. To specify this setting, you must first enable ENA Express. Possible values are: true, false. | Optional |
| enable_primary_ipv6 | If you're modifying a network interface in a dual-stack or IPv6-only subnet, you have the option to assign a primary IPv6 IP address. Possible values are: true, false. | Optional |
| tcp_established_timeout | Timeout (in seconds) for idle TCP connections in an established state. Min is 60 seconds. Max is 432000 seconds. | Optional |
| udp_stream_timeout | Timeout (in seconds) for idle UDP flows classified as streams which have seen more than one request-response transaction. Min is 60 seconds. Max is 180 seconds. | Optional |
| udp_timeout | Timeout (in seconds) for idle UDP flows that have seen traffic only in a single direction or a single request-response transaction. Min is 30 seconds. Max is 60 seconds. | Optional |
| associate_public_ip_address | Indicates whether to assign a public IPv4 address to a network interface. This option can be enabled for any network interface but will only apply to the primary network interface (eth0). Possible values are: true, false. | Optional |
| associated_subnet_ids | A list of comma-separated subnet IDs to associate with the network interface. | Optional |
| description | A description for the network interface. | Optional |
| source_dest_check | Enable or disable source/destination checks, which ensure that the instance is either the source or the destination of any traffic that it receives. If the value is true, source/destination checks are enabled; otherwise, they are disabled. The default value is true. You must disable source/destination checks if the instance runs services such as network address translation, routing, or firewalls. Possible values are: true, false. | Optional |
| groups | A comma-separated list of security groups IDs. Changes the security groups for the network interface. The new set of groups you specify replaces the current set. | Optional |
| default_ena_queue_count | Whether to use the default number of the ENA queues. Possible values are: true, false. | Optional |
| ena_queue_count | The number of ENA queues to be created with the instance. | Optional |
| attachment_id | The ID of the network interface attachment. If modifying the delete on termination attribute, you must specify the ID of the interface attachment. | Optional |
| delete_on_termination | Indicates whether the network interface is deleted when the instance is terminated. If modified, you must specify the ID of the interface attachment. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.NetworkInterfaces.Attribute.ModifyResponseMetadata | Object | The response metadata. |
| AWS.EC2.NetworkInterfaces.NetworkInterfaceId | String | The ID of the network interface. |

### aws-ec2-iam-instance-profile-associations-describe

***
Describes IAM instance profile associations. Required IAM Permission: ec2:DescribeIamInstanceProfileAssociations.

#### Base Command

`aws-ec2-iam-instance-profile-associations-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| association_ids | A comma-separated list of IAM instance profile association IDs. | Optional |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). | Optional |
| limit | The maximum number of results to return. Minimum value of 5. Maximum value of 1000. Default is 50. | Optional |
| next_token | The token for the next set of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.IamInstanceProfileAssociations.AssociationId | String | The ID of the association. |
| AWS.EC2.IamInstanceProfileAssociations.InstanceId | String | The ID of the instance. |
| AWS.EC2.IamInstanceProfileAssociations.IamInstanceProfile.Arn | String | The Amazon Resource Name \(ARN\) of the instance profile. |
| AWS.EC2.IamInstanceProfileAssociations.IamInstanceProfile.Id | String | The ID of the instance profile. |
| AWS.EC2.IamInstanceProfileAssociations.State | String | The state of the association. |
| AWS.EC2.IamInstanceProfileAssociationsNextToken | String | The token for the next set of results. |

### aws-ec2-launch-template-create

***
Creates a launch template. A launch template contains the parameters to launch an instance. Required IAM Permission: ec2:CreateLaunchTemplate.

#### Base Command

`aws-ec2-launch-template-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS Region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| launch_template_name | A name for the launch template. | Required |
| version_description | A description for the first version of the launch template. | Optional |
| kernel_id | The ID of the kernel. | Optional |
| ebs_optimized | Whether the instance is optimized for Amazon EBS I/O. Possible values are: true, false. | Optional |
| iam_instance_profile_arn | The Amazon Resource Name (ARN) of the instance profile. | Optional |
| iam_instance_profile_name | The name of the instance profile. | Optional |
| image_id | The ID of the AMI. | Optional |
| instance_type | The instance type. | Optional |
| key_name | The name of the key pair. | Optional |
| monitoring | Set to true to enable detailed monitoring. Set to false to enable basic monitoring. Possible values are: true, false. | Optional |
| disable_api_termination | If set to true, you can't terminate the instance using the Amazon EC2 console, CLI, or API. Possible values are: true, false. | Optional |
| instance_initiated_shutdown_behavior | Whether an instance stops or terminates when you initiate shutdown from the instance. Possible values are: stop, terminate. | Optional |
| user_data | The Base64-encoded user data to make available to the instance. | Optional |
| security_group_ids | A comma-separated list of security group IDs. | Optional |
| security_groups | A comma-separated list of security group names. | Optional |
| device_name | The device name (for example, /dev/sdh or xvdh). | Optional |
| ebs_encrypted | Indicates whether the EBS volume is encrypted. Possible values are: true, false. | Optional |
| ebs_delete_on_termination | Indicates whether the EBS volume is deleted on instance termination. Possible values are: true, false. | Optional |
| ebs_iops | The number of I/O operations per second (IOPS) that the volume supports. | Optional |
| ebs_kms_key_id | The ARN of the AWS Key Management Service (AWS KMS) CMK used for encryption. | Optional |
| ebs_snapshot_id | The ID of the snapshot. | Optional |
| ebs_volume_size | The size of the volume, in GiB. | Optional |
| ebs_volume_type | The volume type. Possible values are: standard, io1, io2, gp2, gp3, sc1, st1. | Optional |
| ebs_card_index | The index of the EBS card. Some instance types support multiple EBS cards. The default EBS card index is 0. | Optional |
| ebs_throughput | The throughput to provision for a gp3 volume, with a maximum of 2,000 MiB/s. The minimum value of 125, and maximum value of 2,000. | Optional |
| ebs_initialization_rate | Specifies the Amazon EBS Provisioned Rate for Volume Initialization (volume initialization rate), in MiB/s, at which to download the snapshot blocks from Amazon S3 to the volume. | Optional |
| block_device_mappings_no_device | To omit the device from the block device mapping, specify an empty string. | Optional |
| block_device_mappings_virtual_name | The virtual device name (ephemeralN). | Optional |
| network_interfaces_associate_public_ip_address | Associates a public IPv4 address with eth0 for a new network interface. Possible values are: true, false. | Optional |
| network_interfaces_delete_on_termination | Whether the network interface is deleted when the instance is terminated. Possible values are: true, false. | Optional |
| network_interfaces_description | A description for the network interface. | Optional |
| network_interfaces_device_index | The device index for the network interface attachment. | Optional |
| network_interface_groups | A comma-separated list of security group IDs. | Optional |
| subnet_id | The ID of the subnet for the network interface. | Optional |
| private_ip_address | The primary private IPv4 address of the network interface. | Optional |
| ipv6_address_count | The number of IPv6 addresses to assign to a network interface. | Optional |
| ipv6_addresses | One or more specific IPv6 addresses from the IPv6 CIDR block range of your subnet. | Optional |
| network_interface_id | The ID of the network interface. | Optional |
| availability_zone | The Availability Zone for the instance. | Optional |
| placement_tenancy | The tenancy of the instance. Possible values are: default, dedicated, host. | Optional |
| ram_disk_id | The ID of the RAM disk. | Optional |
| tags | The tags to assign to the Elastic IP address. Format: key=&lt;key&gt;,value=&lt;value&gt;;key=&lt;key&gt;,value=&lt;value&gt;. | Optional |
| market_type | The market type. Possible values are: spot, capacity-block, interruptible-capacity-reservation. | Optional |
| spot_options_instance_type | The Spot Instance request type. Possible values are: one-time, persistent. | Optional |
| spot_options_max_price | The maximum hourly price you're willing to pay for the Spot Instances. | Optional |
| spot_options_instance_interruption_behavior | The behavior when a Spot Instance is interrupted. Possible values are: hibernate, stop, terminate. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.LaunchTemplates.LaunchTemplateId | string | The ID of the launch template. |
| AWS.EC2.LaunchTemplates.LaunchTemplateName | string | The name of the launch template. |
| AWS.EC2.LaunchTemplates.CreateTime | date | The time launch template was created. |
| AWS.EC2.LaunchTemplates.CreatedBy | string | The principal that created the launch template. |
| AWS.EC2.LaunchTemplates.DefaultVersionNumber | number | The default version number of the launch template. |
| AWS.EC2.LaunchTemplates.LatestVersionNumber | number | The latest version number of the launch template. |
| AWS.EC2.LaunchTemplates.Tags.Key | string | The key of the tag. |
| AWS.EC2.LaunchTemplates.Tags.Value | string | The value of the tag. |

### aws-ec2-volumes-describe

***
Describes the specified EBS volumes or all of your EBS volumes. Required IAM Permission: ec2:DescribeVolumes.

#### Base Command

`aws-ec2-volumes-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. This is used when running commands across multiple accounts. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| volume_ids | A comma-separated list of volume IDs. | Optional |
| limit | The maximum number of records to return. The valid range is 5-1000. | Optional |
| next_token | The token returned from a previous paginated request. Pagination continues from the end of the items returned by the previous request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Volumes.Attachments.AttachTime | date | The timestamp when the attachment was initiated. |
| AWS.EC2.Volumes.Attachments.Device | string | The device name. |
| AWS.EC2.Volumes.Attachments.InstanceId | string | The ID of the instance. |
| AWS.EC2.Volumes.Attachments.State | string | The attachment state of the volume. |
| AWS.EC2.Volumes.Attachments.VolumeId | string | The ID of the volume. |
| AWS.EC2.Volumes.Attachments.DeleteOnTermination | boolean | Indicates whether the EBS volume is deleted on instance termination. |
| AWS.EC2.Volumes.AvailabilityZone | string | The Availability Zone for the volume. |
| AWS.EC2.Volumes.CreateTime | date | The time stamp when volume creation was initiated. |
| AWS.EC2.Volumes.Encrypted | boolean | Indicates whether the volume is encrypted. |
| AWS.EC2.Volumes.KmsKeyId | string | The Amazon Resource Name \(ARN\) of the AWS Key Management Service \(AWS KMS\) customer master key \(CMK\) that was used to protect the volume encryption key for the volume. |
| AWS.EC2.Volumes.OutpostArn | string | The Amazon Resource Name \(ARN\) of the Outpost. |
| AWS.EC2.Volumes.Size | number | The size of the volume, in GiBs. |
| AWS.EC2.Volumes.SnapshotId | string | The snapshot from which the volume was created, if applicable. |
| AWS.EC2.Volumes.State | string | The volume state. |
| AWS.EC2.Volumes.VolumeId | string | The ID of the volume. |
| AWS.EC2.Volumes.Iops | number | The number of I/O operations per second \(IOPS\). |
| AWS.EC2.Volumes.Tags.Key | string | The key of the tag. |
| AWS.EC2.Volumes.Tags.Value | string | The value of the tag. |
| AWS.EC2.Volumes.VolumeType | string | The volume type. |
| AWS.EC2.Volumes.FastRestored | boolean | Indicates whether the volume was created using fast snapshot restore. |
| AWS.EC2.Volumes.MultiAttachEnabled | boolean | Indicates whether Amazon EBS Multi-Attach is enabled. |
| AWS.EC2.Volumes.Throughput | number | The throughput that the volume supports, in MiB/s. |
| AWS.EC2.Volumes.SseType | string | Reserved for future use. |
| AWS.EC2.VolumesNextToken | String | Token to use for pagination in subsequent requests. |

### aws-ec2-reserved-instances-describe

***
Describes one or more of the Reserved Instances that you purchased. Required IAM Permission: ec2:DescribeReservedInstances.

#### Base Command

`aws-ec2-reserved-instances-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| reserved_instances_ids | A comma-separated list of Reserved Instance IDs. | Optional |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). | Optional |
| offering_class | The offering class of the Reserved Instance. Possible values are: standard, convertible. | Optional |
| offering_type | The Reserved Instance offering type. Possible values are: Heavy Utilization, Medium Utilization, Light Utilization, No Upfront, Partial Upfront, All Upfront. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.ReservedInstances.ReservedInstancesId | String | The ID of the Reserved Instance. |
| AWS.EC2.ReservedInstances.InstanceType | String | The instance type on which the Reserved Instance can be used. |
| AWS.EC2.ReservedInstances.AvailabilityZone | String | The Availability Zone in which the Reserved Instance can be used. |
| AWS.EC2.ReservedInstances.Start | Date | The date and time the Reserved Instance started. |
| AWS.EC2.ReservedInstances.End | Date | The time when the Reserved Instance expires. |
| AWS.EC2.ReservedInstances.Duration | Number | The duration of the Reserved Instance, in seconds. |
| AWS.EC2.ReservedInstances.UsagePrice | Number | The usage price of the Reserved Instance, per hour. |
| AWS.EC2.ReservedInstances.FixedPrice | Number | The purchase price of the Reserved Instance. |
| AWS.EC2.ReservedInstances.InstanceCount | Number | The number of reservations purchased. |
| AWS.EC2.ReservedInstances.ProductDescription | String | The Reserved Instance product platform description. |
| AWS.EC2.ReservedInstances.State | String | The state of the Reserved Instance purchase. |
| AWS.EC2.ReservedInstances.CurrencyCode | String | The currency of the Reserved Instance. |
| AWS.EC2.ReservedInstances.InstanceTenancy | String | The tenancy of the instance. |
| AWS.EC2.ReservedInstances.OfferingClass | String | The offering class of the Reserved Instance. |
| AWS.EC2.ReservedInstances.OfferingType | String | The Reserved Instance offering type. |
| AWS.EC2.ReservedInstances.RecurringCharges.Amount | Number | The amount of the recurring charge. |
| AWS.EC2.ReservedInstances.RecurringCharges.Frequency | String | The frequency of the recurring charge. |
| AWS.EC2.ReservedInstances.Scope | String | The scope of the Reserved Instance. |
| AWS.EC2.ReservedInstances.Tags.Key | String | The key of the tag. |
| AWS.EC2.ReservedInstances.Tags.Value | String | The value of the tag. |

### aws-ec2-address-disassociate

***
Disassociates an Elastic IP address from the instance or network interface it's associated with. Required IAM Permission: ec2:DisassociateAddress.

#### Base Command

`aws-ec2-address-disassociate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| association_id | The association ID. Required for VPC. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-instances-unmonitor

***
Disables detailed monitoring for one or more running Amazon EC2 instances. Required IAM Permission: ec2:UnmonitorInstances.

#### Base Command

`aws-ec2-instances-unmonitor`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_ids | A comma-separated list of instance IDs to disable monitoring for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Instances.InstanceId | String | The ID of the instance. |
| AWS.EC2.Instances.Monitoring.State | String | The monitoring state \(disabled | disabling | enabled | pending\). |

### aws-ec2-launch-template-delete

***
Deletes a launch template. Deleting a launch template deletes all of its versions. Required IAM Permission: ec2:DeleteLaunchTemplate.

#### Base Command

`aws-ec2-launch-template-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| launch_template_id | The ID of the launch template. You must specify either the launch template ID or launch template name, but not both. | Optional |
| launch_template_name | The name of the launch template. You must specify either the launch template ID or launch template name, but not both. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.DeletedLaunchTemplates.LaunchTemplateId | string | The ID of the launch template. |
| AWS.EC2.DeletedLaunchTemplates.LaunchTemplateName | string | The name of the launch template. |
| AWS.EC2.DeletedLaunchTemplates.CreateTime | date | The time launch template was created. |
| AWS.EC2.DeletedLaunchTemplates.CreatedBy | string | The principal that created the launch template. |
| AWS.EC2.DeletedLaunchTemplates.DefaultVersionNumber | number | The default version number of the launch template. |
| AWS.EC2.DeletedLaunchTemplates.LatestVersionNumber | number | The latest version number of the launch template. |
| AWS.EC2.DeletedLaunchTemplates.Operator | Object | The entity that manages the launch template. |
| AWS.EC2.DeletedLaunchTemplates.Tags.Key | string | The key of the tag. |
| AWS.EC2.DeletedLaunchTemplates.Tags.Value | string | The value of the tag. |

### aws-ec2-password-data-get

***
Retrieves the encrypted administrator password for a running Windows instance. Required IAM Permission: ec2:GetPasswordData.

#### Base Command

`aws-ec2-password-data-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_id | The ID of the Windows instance. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Instances.PasswordData.InstanceId | String | The ID of the instance. |
| AWS.EC2.Instances.PasswordData.PasswordData | String | The password of the instance. Returns an empty string if the password is not available. |
| AWS.EC2.Instances.PasswordData.Timestamp | Date | The time the data was last updated. |
| AWS.EC2.Instances.InstanceId | String | The ID of the instance. |

### aws-ec2-volume-attach

***
Attaches an EBS volume to a running or stopped instance and exposes it to the instance with the specified device name. Required IAM Permission: ec2:AttachVolume.

#### Base Command

`aws-ec2-volume-attach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. This is used when running commands across multiple accounts. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| device | The device name (for example, /dev/sdh or xvdh). | Required |
| instance_id | The ID of the instance. | Required |
| volume_id | The ID of the EBS volume. The volume and instance must be within the same Availability Zone. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Volumes.VolumeId | string | The ID of the volume. |
| AWS.EC2.Volumes.Attachments.AttachTime | date | The timestamp when the attachment was initiated. |
| AWS.EC2.Volumes.Attachments.Device | string | The device name. |
| AWS.EC2.Volumes.Attachments.InstanceId | string | The ID of the instance. |
| AWS.EC2.Volumes.Attachments.State | string | The attachment state of the volume. |
| AWS.EC2.Volumes.Attachments.VolumeId | string | The ID of the volume. |
| AWS.EC2.Volumes.Attachments.DeleteOnTermination | boolean | Indicates whether the EBS volume is deleted on instance termination. |
| AWS.EC2.Volumes.Attachments.AssociatedResource | string | The ARN of the Amazon ECS or Fargate task to which the volume is attached. |
| AWS.EC2.Volumes.Attachments.InstanceOwningService | string | The service principal of Amazon Web Services service that owns the underlying instance to which the volume is attached. |

### aws-ec2-launch-templates-describe

***
Describes one or more launch templates. Required IAM Permission: ec2:DescribeLaunchTemplates.

#### Base Command

`aws-ec2-launch-templates-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS Region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| launch_template_ids | A comma-separated list of launch template IDs. | Optional |
| launch_template_names | A comma-separated list of launch template names. | Optional |
| limit | The maximum number of results to return in a single call. Maximum value of 200. | Optional |
| next_token | The token for the next set of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.LaunchTemplatesNextToken | String | Token to use for pagination in subsequent requests. |
| AWS.EC2.LaunchTemplates.LaunchTemplateId | string | The ID of the launch template. |
| AWS.EC2.LaunchTemplates.LaunchTemplateName | string | The name of the launch template. |
| AWS.EC2.LaunchTemplates.CreateTime | date | The time launch template was created. |
| AWS.EC2.LaunchTemplates.CreatedBy | string | The principal that created the launch template. |
| AWS.EC2.LaunchTemplates.DefaultVersionNumber | number | The default version number of the launch template. |
| AWS.EC2.LaunchTemplates.LatestVersionNumber | number | The latest version number of the launch template. |
| AWS.EC2.LaunchTemplates.Tags.Key | string | The key of the tag. |
| AWS.EC2.LaunchTemplates.Tags.Value | string | The value of the tag. |

### aws-ec2-address-release

***
Releases the specified Elastic IP address. After releasing an Elastic IP address, it is released to the IP address pool and might be unavailable to you. Required IAM Permission: ec2:ReleaseAddress.

#### Base Command

`aws-ec2-address-release`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| allocation_id | The allocation ID. Required for VPC. | Optional |
| network_border_group | The set of Availability Zones, Local Zones, or Wavelength Zones from which AWS advertises IP addresses. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-addresses-describe

***
Describes one or more of your Elastic IP addresses. Required IAM Permission: ec2:DescribeAddresses.

#### Base Command

`aws-ec2-addresses-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| public_ips | One or more Elastic IP addresses, separated by commas. | Optional |
| allocation_ids | One or more allocation IDs, separated by commas. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.ElasticIPs.PublicIp | string | The Elastic IP address. |
| AWS.EC2.ElasticIPs.AllocationId | string | The ID representing the allocation of the address. |
| AWS.EC2.ElasticIPs.Domain | string | The network \(vpc or standard\). |
| AWS.EC2.ElasticIPs.InstanceId | string | The ID of the instance the address is associated with \(if any\). |
| AWS.EC2.ElasticIPs.AssociationId | string | The ID representing the association of the address with an instance. |
| AWS.EC2.ElasticIPs.NetworkInterfaceId | string | The ID of the network interface. |
| AWS.EC2.ElasticIPs.NetworkInterfaceOwnerId | string | The ID of the AWS account that owns the network interface. |
| AWS.EC2.ElasticIPs.PrivateIpAddress | string | The private IP address associated with the Elastic IP address. |
| AWS.EC2.ElasticIPs.Tags.Key | string | The key of the tag. |
| AWS.EC2.ElasticIPs.Tags.Value | string | The value of the tag. |
| AWS.EC2.ElasticIPs.PublicIpv4Pool | string | The ID of an address pool. |
| AWS.EC2.ElasticIPs.NetworkBorderGroup | string | The name of the unique set of Availability Zones, Local Zones, or Wavelength Zones from which AWS advertises IP addresses. |
| AWS.EC2.ElasticIPs.CustomerOwnedIp | string | The customer-owned IP address. |
| AWS.EC2.ElasticIPs.CustomerOwnedIpv4Pool | string | The ID of the customer-owned address pool. |
| AWS.EC2.ElasticIPs.CarrierIp | string | The carrier IP address associated. |

### aws-lambda-layer-version-delete

***
Deletes a version of a Lambda layer. Required IAM Permission: lambda:DeleteLayerVersion.

#### Base Command

`aws-lambda-layer-version-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| layer_name | The name or Amazon Resource Name (ARN) of the layer. | Required |
| version_number | The version number to delete. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-instances-reboot

***
Requests a reboot of one or more instances. This operation is asynchronous; it only queues a request to reboot the specified instances. Required IAM Permission: ec2:RebootInstances.

#### Base Command

`aws-ec2-instances-reboot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_ids | A comma-separated list of instance IDs to reboot. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-volume-create

***
Creates an EBS volume that can be attached to an instance in the same Availability Zone. Required IAM Permission: ec2:CreateVolume.

#### Base Command

`aws-ec2-volume-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. This is used when running commands across multiple accounts. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| availability_zone | The Availability Zone in which to create the volume. | Required |
| encrypted | Specifies whether the volume should be encrypted. Possible values are: true, false. | Optional |
| iops | The number of I/O operations per second (IOPS). For gp3, io1, and io2 volumes, this represents the number of IOPS that are provisioned for the volume. | Optional |
| kms_key_id | The identifier of the AWS KMS key to use for Amazon EBS encryption. If this parameter is not specified, your AWS managed key for Amazon EBS is used. | Optional |
| outpost_arn | The Amazon Resource Name (ARN) of the Outpost. | Optional |
| size | The size of the volume, in GiBs. You must specify either a snapshot ID or a volume size. | Optional |
| snapshot_id | The snapshot from which to create the volume. You must specify either a snapshot ID or a volume size. | Optional |
| volume_type | The volume type. Possible values are: standard, io1, io2, gp2, gp3, sc1, st1. | Optional |
| throughput | The throughput to provision for a volume, with a maximum of 1,000 MiB/s. This parameter is valid only for gp3 volumes. | Optional |
| multi_attach_enabled | Indicates whether to enable Amazon EBS Multi-Attach. If you enable Multi-Attach, you can attach the volume to up to 16 Nitro-based instances in the same Availability Zone. This parameter is supported with io1 and io2 volumes only. Possible values are: true, false. | Optional |
| tags | One or more tags. Example key=Name,value=test;key=Owner,value=Bob. | Optional |
| client_token | Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Volumes.Attachments.AttachTime | date | The timestamp when the attachment was initiated. |
| AWS.EC2.Volumes.Attachments.Device | string | The device name. |
| AWS.EC2.Volumes.Attachments.InstanceId | string | The ID of the instance. |
| AWS.EC2.Volumes.Attachments.State | string | The attachment state of the volume. |
| AWS.EC2.Volumes.Attachments.VolumeId | string | The ID of the volume. |
| AWS.EC2.Volumes.Attachments.DeleteOnTermination | boolean | Indicates whether the EBS volume is deleted on instance termination. |
| AWS.EC2.Volumes.AvailabilityZone | string | The Availability Zone for the volume. |
| AWS.EC2.Volumes.CreateTime | date | The time stamp when volume creation was initiated. |
| AWS.EC2.Volumes.Encrypted | boolean | Indicates whether the volume is encrypted. |
| AWS.EC2.Volumes.KmsKeyId | string | The Amazon Resource Name \(ARN\) of the AWS Key Management Service \(AWS KMS\) customer master key \(CMK\) that was used to protect the volume encryption key for the volume. |
| AWS.EC2.Volumes.OutpostArn | string | The Amazon Resource Name \(ARN\) of the Outpost. |
| AWS.EC2.Volumes.Size | number | The size of the volume, in GiBs. |
| AWS.EC2.Volumes.SnapshotId | string | The snapshot from which the volume was created, if applicable. |
| AWS.EC2.Volumes.State | string | The volume state. |
| AWS.EC2.Volumes.VolumeId | string | The ID of the volume. |
| AWS.EC2.Volumes.Iops | number | The number of I/O operations per second \(IOPS\). |
| AWS.EC2.Volumes.Tags.Key | string | The key of the tag. |
| AWS.EC2.Volumes.Tags.Value | string | The value of the tag. |
| AWS.EC2.Volumes.VolumeType | string | The volume type. |
| AWS.EC2.Volumes.FastRestored | boolean | Indicates whether the volume was created using fast snapshot restore. |
| AWS.EC2.Volumes.MultiAttachEnabled | boolean | Indicates whether Amazon EBS Multi-Attach is enabled. |
| AWS.EC2.Volumes.Throughput | number | The throughput that the volume supports, in MiB/s. |
| AWS.EC2.Volumes.SseType | string | Reserved for future use. |

### aws-ec2-instance-terminated-waiter

***
Waits until the specified EC2 instances reach the 'terminated' state. Checks every `waiter_delay` seconds until successful or until the maximum number of attempts (`waiter_max_attempts`) is reached. Required IAM Permission: ec2:DescribeInstances.

#### Base Command

`aws-ec2-instance-terminated-waiter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_ids | A comma-separated list of instance IDs to wait for. | Optional |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). | Optional |
| waiter_delay | The amount of time in seconds to wait between attempts. Default is 15. Default is 15. | Optional |
| waiter_max_attempts | The maximum number of attempts to be made. Default is 40. Default is 40. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-address-allocate

***
Allocates an Elastic IP address to your AWS account. After you allocate the Elastic IP address you can associate it with an instance or network interface. Required IAM Permission: ec2:AllocateAddress.

#### Base Command

`aws-ec2-address-allocate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| address | The Elastic IP address to recover or an IPv4 address from an address pool. | Optional |
| public_ipv4_pool | The ID of an address pool that you own. Use this parameter to let Amazon EC2 select an address from the address pool. | Optional |
| network_border_group | A unique set of Availability Zones, Local Zones, or Wavelength Zones from which AWS advertises IP addresses. | Optional |
| customer_owned_ipv4_pool | The ID of a customer-owned address pool. | Optional |
| tag_specifications | The tags to assign to the Elastic IP address. Format: key=&lt;key&gt;,value=&lt;value&gt;;key=&lt;key&gt;,value=&lt;value&gt;. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.ElasticIPs.PublicIp | string | The Elastic IP address. |
| AWS.EC2.ElasticIPs.AllocationId | string | The ID that represents the allocation of the Elastic IP address. |
| AWS.EC2.ElasticIPs.Domain | string | The network \(vpc or standard\). |
| AWS.EC2.ElasticIPs.PublicIpv4Pool | string | The ID of an address pool. |
| AWS.EC2.ElasticIPs.NetworkBorderGroup | string | The name of the unique set of Availability Zones, Local Zones, or Wavelength Zones. |
| AWS.EC2.ElasticIPs.CustomerOwnedIp | string | The customer-owned IP address. |
| AWS.EC2.ElasticIPs.CustomerOwnedIpv4Pool | string | The ID of the customer-owned address pool. |
| AWS.EC2.ElasticIPs.CarrierIp | string | The carrier IP address. |

### aws-ec2-address-associate

***
Associates an Elastic IP address, or carrier IP address (for instances that are in subnets in Wavelength Zones) with an instance or a network interface. Required IAM Permission: ec2:AssociateAddress.

#### Base Command

`aws-ec2-address-associate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| allocation_id | The allocation ID. | Required |
| instance_id | The ID of the instance. The instance must have exactly one attached network interface. | Optional |
| network_interface_id | The ID of the network interface. | Optional |
| private_ip_address | The primary or secondary private IP address to associate with the Elastic IP address. | Optional |
| allow_reassociation | Whether to allow an Elastic IP address that is already associated with another network interface or instance to be reassociated with the specified instance or network interface. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.ElasticIPs.AllocationId | string | The allocation ID. |
| AWS.EC2.ElasticIPs.AssociationId | string | The ID that represents the association of the Elastic IP address with an instance. |

### aws-lambda-layer-version-publish

***
Creates a Lambda layer from a ZIP archive. Required IAM Permission: lambda:PublishLayerVersion.

#### Base Command

`aws-lambda-layer-version-publish`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| layer_name | The name of the layer. | Required |
| description | The description of the version. | Optional |
| zip_file | The entry ID of the uploaded ZIP file containing the layer code. | Optional |
| s3_bucket | The Amazon S3 bucket of the layer archive. | Optional |
| s3_key | The Amazon S3 key of the layer archive. | Optional |
| s3_object_version | For versioned objects, the version of the layer archive object to use. | Optional |
| compatible_runtimes | A list of compatible function runtimes. | Optional |
| compatible_architectures | A list of compatible instruction set architectures. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.LayerVersions.LayerVersionArn | string | The ARN of the layer version. |
| AWS.Lambda.LayerVersions.LayerArn | string | The ARN of the layer. |
| AWS.Lambda.LayerVersions.Description | string | The description of the version. |
| AWS.Lambda.LayerVersions.CreatedDate | string | The date that the layer version was created, in ISO 8601 format. |
| AWS.Lambda.LayerVersions.Version | number | The version number. |
| AWS.Lambda.LayerVersions.CompatibleRuntimes | array | The layer's compatible runtimes. |
| AWS.Lambda.LayerVersions.CompatibleArchitectures | array | A list of compatible instruction set architectures. |
| AWS.Lambda.LayerVersions.Region | string | The AWS Region. |

### aws-ec2-volume-modify

***
You can modify several parameters of an existing EBS volume, including volume size, volume type, and IOPS capacity. Required IAM Permission: ec2:ModifyVolume.

#### Base Command

`aws-ec2-volume-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. This is used when running commands across multiple accounts. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| volume_id | The ID of the volume. | Required |
| size | Target size in GiB of the volume to be modified. | Optional |
| volume_type | Target EBS volume type of the volume to be modified. The API does not support modifications for volume type standard. Possible values are: gp2, gp3, io1, io2, sc1, st1. | Optional |
| iops | Target IOPS rate of the volume to be modified. | Optional |
| throughput | Target throughput of the volume to be modified, in MiB/s. Valid only for gp3 volumes. | Optional |
| multi_attach_enabled | Specifies whether to enable Amazon EBS Multi-Attach. Valid only for io1 and io2 volumes. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Volumes.VolumeId | string | The ID of the volume. |
| AWS.EC2.Volumes.Modification.ModificationState | string | The current modification state. |
| AWS.EC2.Volumes.Modification.StatusMessage | string | A status message about the modification progress or failure. |
| AWS.EC2.Volumes.Size | number | The target size of the volume, in GiB. |
| AWS.EC2.Volumes.Iops | number | The target IOPS rate of the volume. |
| AWS.EC2.Volumes.VolumeType | string | The target EBS volume type of the volume. |
| AWS.EC2.Volumes.Throughput | number | The target throughput of the volume, in MiB/s. |
| AWS.EC2.Volumes.MultiAttachEnabled | boolean | The target setting for Amazon EBS Multi-Attach. |
| AWS.EC2.Volumes.Modification.OriginalSize | number | The original size of the volume, in GiB. |
| AWS.EC2.Volumes.Modification.OriginalIops | number | The original IOPS rate of the volume. |
| AWS.EC2.Volumes.Modification.OriginalVolumeType | string | The original EBS volume type of the volume. |
| AWS.EC2.Volumes.Modification.OriginalThroughput | number | The original throughput of the volume, in MiB/s. |
| AWS.EC2.Volumes.Modification.OriginalMultiAttachEnabled | boolean | The original setting for Amazon EBS Multi-Attach. |
| AWS.EC2.Volumes.Modification.Progress | number | The modification progress, from 0 to 100 percent complete. |
| AWS.EC2.Volumes.Modification.StartTime | date | The modification start time. |
| AWS.EC2.Volumes.Modification.EndTime | date | The modification completion or failure time. |

### aws-ec2-instance-stopped-waiter

***
Waits until EC2 instances are in the 'stopped' state. Checks every `waiter_delay` seconds until successful or until the maximum number of attempts (`waiter_max_attempts`) is reached. Required IAM Permission: ec2:DescribeInstances.

#### Base Command

`aws-ec2-instance-stopped-waiter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_ids | A comma-separated list of instance IDs to wait for. | Optional |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). | Optional |
| waiter_delay | The amount of time in seconds to wait between attempts. Default is 15. Default is 15. | Optional |
| waiter_max_attempts | The maximum number of attempts to be made. Default is 40. Default is 40. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-volume-delete

***
Deletes the specified EBS volume. The volume must be in the available state (not attached to an instance). Required IAM Permission: ec2:DeleteVolume.

#### Base Command

`aws-ec2-volume-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. This is used when running commands across multiple accounts. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| volume_id | The ID of the volume. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-volume-detach

***
Detaches an EBS volume from an instance. Required IAM Permission: ec2:DetachVolume.

#### Base Command

`aws-ec2-volume-detach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. This is used when running commands across multiple accounts. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| volume_id | The ID of the volume. | Required |
| force | Forces detachment if the previous detachment attempt did not occur cleanly. This option can lead to data loss or a corrupted file system. Use this option only as a last resort to detach a volume from a failed instance. Possible values are: true, false. | Optional |
| device | The device name (for example, /dev/sdh or xvdh). | Optional |
| instance_id | The ID of the instance. If you are detaching a Multi-Attach enabled volume, you must specify an instance ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Volumes.VolumeId | string | The ID of the volume. |
| AWS.EC2.Volumes.Attachments.AttachTime | date | The timestamp when the attachment was initiated. |
| AWS.EC2.Volumes.Attachments.Device | string | The device name. |
| AWS.EC2.Volumes.Attachments.InstanceId | string | The ID of the instance. |
| AWS.EC2.Volumes.Attachments.State | string | The attachment state of the volume. |
| AWS.EC2.Volumes.Attachments.VolumeId | string | The ID of the volume. |
| AWS.EC2.Volumes.Attachments.DeleteOnTermination | boolean | Indicates whether the EBS volume is deleted on instance termination. |
| AWS.EC2.Volumes.Attachments.AssociatedResource | string | The ARN of the Amazon ECS or Fargate task to which the volume is attached. |
| AWS.EC2.Volumes.Attachments.InstanceOwningService | string | The AWS service principal that owns the instance to which the volume is attached. |

### aws-ec2-instance-status-ok-waiter

***
Waits until EC2 instance status checks pass. Checks every `waiter_delay` seconds until successful or until the maximum number of attempts (`waiter_max_attempts`) is reached. Required IAM Permission: ec2:DescribeInstanceStatus.

#### Base Command

`aws-ec2-instance-status-ok-waiter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_ids | A comma-separated list of instance IDs to wait for. | Optional |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). | Optional |
| waiter_delay | The amount of time in seconds, to wait between attempts. Default is 15. Default is 15. | Optional |
| waiter_max_attempts | The maximum number of attempts to be made. Default is 40. Default is 40. | Optional |
| include_all_instances | When true, includes the health status for all instances. When false, includes the health status for running instances only. Possible values are: true, false. Default is false. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-instance-running-waiter

***
Waits until the specified EC2 instances reach the 'running' state. Checks the status every `waiter_delay` seconds until successful or until `waiter_max_attempts` is reached (default maximum attempts: `waiter_max_attempts`). Required IAM Permission: ec2:DescribeInstances.

#### Base Command

`aws-ec2-instance-running-waiter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_ids | A comma-separated list of instance IDs to wait for. | Optional |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). | Optional |
| waiter_delay | The amount of time in seconds to wait between attempts. Default is 15. Default is 15. | Optional |
| waiter_max_attempts | The maximum number of attempts to be made. Default is 40. Default is 40. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-instances-monitor

***
Enables detailed monitoring on one or more running Amazon EC2 instances. Required IAM Permission: ec2:MonitorInstances.

#### Base Command

`aws-ec2-instances-monitor`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| instance_ids | A comma-separated list of instance IDs to enable monitoring for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Instances.InstanceId | String | The ID of the instance. |
| AWS.EC2.Instances.Monitoring.State | String | The monitoring state \(disabled | disabling | enabled | pending\). |

### aws-s3-bucket-delete

***
Delete AWS S3 bucket, the bucket must be empty from files. Required IAM Permission: s3:DeleteBucket.

#### Base Command

`aws-s3-bucket-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket | The name of S3 bucket. | Required |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

There is no context output for this command.

### aws-s3-bucket-objects-list

***
Returns some or all (up to 1,000) of the objects in a bucket. Required IAM Permission: s3:ListBucket.

#### Base Command

`aws-s3-bucket-objects-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket | The name of S3 bucket. | Required |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| delimiter | A delimiter is a character (like a slash /) used to bundle files into folders. It turns a long list of file names into an organized, clickable hierarchy. | Optional |
| prefix | Restricts the response to include only those keys that begin with the specified string. This is commonly used to filter results to a specific folder or category. | Optional |
| next_token | The next_token is the marker where you want Amazon S3 to start listing from. Amazon S3 starts listing after this specified key. Marker can be any key in the bucket. | Optional |
| limit | Specifies the maximum number of keys to return in the response, ranging from 1 to 1,000. Default: 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3.Buckets.BucketName | String | The name of S3 bucket. |
| AWS.S3.Buckets.Objects.Key | String | The name of S3 object. |
| AWS.S3.Buckets.Objects.Size | Number | Object size in bytes. |
| AWS.S3.Buckets.Objects.LastModified | String | Last date object was modified. |
| AWS.S3.Buckets.Objects.StorageClass | String | The storage class of the object. |
| AWS.S3.Buckets.Objects.ChecksumType | Array | The checksum algorithm used to calculate the object checksum. |
| AWS.S3.Buckets.Objects.ETag | String | The entity tag \(hash\) of the object. |
| AWS.S3.Buckets.ObjectsNextToken | String | Token to use for pagination in subsequent requests. |

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

### aws-ec2-images-describe

***
Describes the specified images (AMIs, AKIs, and ARIs) available to you or all of the images available to you. Required IAM Permission: ec2:DescribeImages.

#### Base Command

`aws-ec2-images-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| image_ids | A comma-separated list of image IDs to describe. | Optional |
| owners | Filters the images by the owner. Specify an AWS account ID, self (owner is the sender of the request), or an AWS owner alias (valid values are amazon \| aws-marketplace \| microsoft). Omitting this option returns all images for which you have launch permissions, regardless of ownership. Separated by a comma. | Optional |
| executable_users | Scopes the images by users with explicit launch permissions. Specify an AWS account ID, self (the sender of the request), or all (public AMIs). Separated by a comma. | Optional |
| include_deprecated | Specifies whether to include deprecated AMIs. If not specified, the default behavior is determined by the AWS API. Possible values are: true, false. | Optional |
| include_disabled | Specifies whether to include disabled AMIs. If not specified, the default behavior is determined by the AWS API. Possible values are: true, false. | Optional |
| limit | Maximum number of AMIs to be returned in response. | Optional |
| next_token | The token for the next set of AMIs to return. Use value from AWS.EC2.ImagesNextPageToken if available; otherwise, use the token from the output file header. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Images.Architecture | string | The architecture of the image. |
| AWS.EC2.Images.CreationDate | date | The date and time the image was created. |
| AWS.EC2.Images.ImageId | string | The ID of the AMI. |
| AWS.EC2.Images.ImageLocation | string | The location of the AMI. |
| AWS.EC2.Images.ImageType | string | The type of image. |
| AWS.EC2.Images.Public | boolean | Indicates whether the image has public launch permissions. |
| AWS.EC2.Images.KernelId | string | The kernel associated with the image, if any. |
| AWS.EC2.Images.OwnerId | string | The AWS account ID of the image owner. |
| AWS.EC2.Images.Platform | string | The value is Windows for Windows AMIs; otherwise blank. |
| AWS.EC2.Images.ProductCodes.ProductCodeId | string | The product code. |
| AWS.EC2.Images.ProductCodes.ProductCodeType | string | The type of product code. |
| AWS.EC2.Images.RamdiskId | string | The RAM disk associated with the image, if any. |
| AWS.EC2.Images.State | string | The current state of the AMI. |
| AWS.EC2.Images.BlockDeviceMappings.DeviceName | string | The device name. |
| AWS.EC2.Images.BlockDeviceMappings.VirtualName | string | The virtual device name. |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.Encrypted | boolean | Indicates whether the EBS volume is encrypted. |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.DeleteOnTermination | boolean | Indicates whether the EBS volume is deleted upon instance termination. |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.Iops | number | The number of input/output operations per second \(IOPS\). |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.KmsKeyId | string | Identifier for a user-managed CMK under which the EBS volume is encrypted. |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.SnapshotId | string | The ID of the snapshot. |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.VolumeSize | number | The size of the EBS volume, in GiB. |
| AWS.EC2.Images.BlockDeviceMappings.Ebs.VolumeType | string | The volume type. |
| AWS.EC2.Images.BlockDeviceMappings.NoDevice | string | Suppresses the specified device included in the block device mapping. |
| AWS.EC2.Images.Description | string | The description of the AMI. |
| AWS.EC2.Images.EnaSupport | boolean | Specifies whether enhanced networking with ENA is enabled. |
| AWS.EC2.Images.Hypervisor | string | The hypervisor type of the image. |
| AWS.EC2.Images.ImageOwnerAlias | string | The AWS account alias or AWS account ID of the AMI owner. |
| AWS.EC2.Images.Name | string | The name of the AMI. |
| AWS.EC2.Images.RootDeviceName | string | The device name of the root device volume. |
| AWS.EC2.Images.RootDeviceType | string | The type of root device used by the AMI. |
| AWS.EC2.Images.SriovNetSupport | string | Indicates whether enhanced networking with the Intel 82599 VF interface is enabled. |
| AWS.EC2.Images.StateReason.Code | string | The reason code for the state change. |
| AWS.EC2.Images.StateReason.Message | string | The message for the state change. |
| AWS.EC2.Images.Tags.Key | string | The key of the tag. |
| AWS.EC2.Images.Tags.Value | string | The value of the tag. |
| AWS.EC2.Images.VirtualizationType | string | The type of virtualization of the AMI. |
| AWS.EC2.Images.BootMode | string | The boot mode of the image. |
| AWS.EC2.Images.DeprecationTime | string | The date and time to deprecate the AMI. |
| AWS.EC2.Images.ImdsSupport | string | If v2.0, it indicates that IMDSv2 is specified in the AMI. |
| AWS.EC2.Images.SourceInstanceId | string | The ID of the instance that the AMI was created from. |
| AWS.EC2.Images.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. |

### aws-ec2-image-create

***
Creates an Amazon Machine Image (AMI) from an Amazon EBS-backed instance. The instance must be in the running or stopped state. Required IAM Permission: ec2:CreateImage.

#### Base Command

`aws-ec2-image-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| name | A name for the new image. | Required |
| instance_id | The ID of the instance. | Required |
| description | A description for the new image. | Optional |
| no_reboot | By default, Amazon EC2 attempts to shut down and reboot the instance before creating the image. If the No Reboot option is set, Amazon EC2 doesn't shut down the instance before creating the image. Possible values are: true, false. | Optional |
| block_device_mappings | The block devices for the instance in JSON format. | Optional |
| tag_specifications | The tags to apply to the AMI and snapshots on creation. Must be separated by a semicolon (;) and specified using the format "key=key,value=val". | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Images.ImageId | string | The ID of the new AMI. |
| AWS.EC2.Images.Name | string | The name of the new AMI. |
| AWS.EC2.Images.InstanceId | string | The ID of the instance used to create the AMI. |
| AWS.EC2.Images.Region | string | The AWS region where the AMI was created. |

### aws-ec2-image-deregister

***
Deregisters the specified Amazon Machine Image (AMI). After you deregister an AMI, it can't be used to launch new instances. However, it doesn't affect any instances that you've already launched from the AMI. Required IAM Permission: ec2:DeregisterImage.

#### Base Command

`aws-ec2-image-deregister`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| image_id | The ID of the AMI to deregister. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-image-copy

***
Initiates the copy of an AMI from the specified source region to the current region. You can copy an AMI across regions to enable consistent global deployment. Required IAM Permission: ec2:CopyImage.

#### Base Command

`aws-ec2-image-copy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| name | A name for the new AMI in the destination region. | Required |
| source_image_id | The ID of the AMI to copy. | Required |
| source_region | The name of the region that contains the AMI to copy. | Required |
| description | A description for the new AMI in the destination region. | Optional |
| encrypted | Specifies whether the destination snapshots of the copied image should be encrypted. Possible values are: true, false. | Optional |
| kms_key_id | The identifier of the symmetric AWS KMS key to use when creating encrypted volumes. If this parameter is not specified, your AWS managed key for Amazon EBS is used. | Optional |
| client_token | Unique, case-sensitive identifier you provide to ensure idempotency of the request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Images.ImageId | string | The ID of the new AMI. |
| AWS.EC2.Images.Name | string | The name of the new AMI. |
| AWS.EC2.Images.SourceImageId | string | The ID of the source AMI. |
| AWS.EC2.Images.SourceRegion | string | The source region from which the AMI was copied. |
| AWS.EC2.Images.Region | string | The region to which the AMI was copied. |

### aws-ec2-image-available-waiter

***
Waits until an AMI is in the 'available' state. This command polls the AMI status until it becomes available or the maximum wait time is reached. Required IAM Permission: ec2:DescribeImages.

#### Base Command

`aws-ec2-image-available-waiter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| image_ids | A comma-separated list of image IDs to wait for. | Optional |
| owners | Filters the images by the owner. Specify an AWS account ID, self (owner is the sender of the request), or an AWS owner alias (valid values are amazon \| aws-marketplace \| microsoft). Separated by a comma. | Optional |
| executable_users | Scopes the images by users with explicit launch permissions. Specify an AWS account ID, self (the sender of the request), or all (public AMIs). Separated by a comma. | Optional |
| waiter_delay | The amount of time in seconds to wait between attempts. Default is 15 seconds. Default is 15. | Optional |
| waiter_max_attempts | The maximum number of attempts to check the image status. Default is 40 attempts. Default is 40. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-snapshots-describe

***
Describes the EBS snapshots available to you or all snapshots accessible in your environment. Required IAM Permission: ec2:DescribeSnapshots.

#### Base Command

`aws-ec2-snapshots-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| limit | The maximum number of snapshots to return for this request. This value can be between 5 and 1000. | Optional |
| next_token | The token returned from the previous paginated request. Use it to continue retrieving results from where the last request ended. | Optional |
| owner_ids | A comma-separated list of possible owners IDs. Scopes the results to snapshots with the specified owners. | Optional |
| restorable_by_user_ids | A comma-separated list of IDs of the AWS accounts that can create volumes from the snapshot. | Optional |
| snapshot_ids | A comma-separated list of snapshot IDs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Snapshots.DataEncryptionKeyId | string | The data encryption key identifier for the snapshot. |
| AWS.EC2.Snapshots.Description | string | The description for the snapshot. |
| AWS.EC2.Snapshots.Encrypted | boolean | Indicates whether the snapshot is encrypted. |
| AWS.EC2.Snapshots.KmsKeyId | string | The Amazon Resource Name \(ARN\) of the AWS KMS key that was used to protect the volume encryption key for the parent volume. |
| AWS.EC2.Snapshots.OwnerId | string | The ID of the AWS account that owns the EBS snapshot. |
| AWS.EC2.Snapshots.Progress | string | The progress of the snapshot, as a percentage. |
| AWS.EC2.Snapshots.SnapshotId | string | The ID of the snapshot. Each snapshot receives a unique identifier when it is created. |
| AWS.EC2.Snapshots.StartTime | date | The time stamp when the snapshot was initiated. |
| AWS.EC2.Snapshots.State | string | The snapshot state. |
| AWS.EC2.Snapshots.StateMessage | string | Encrypted Amazon EBS snapshots are copied asynchronously. If a snapshot copy operation fails, this field displays error state details to help you diagnose why the error occurred. |
| AWS.EC2.Snapshots.VolumeId | string | The ID of the volume that was used to create the snapshot. |
| AWS.EC2.Snapshots.VolumeSize | number | The size of the volume, in GiB. |
| AWS.EC2.Snapshots.OwnerAlias | string | The AWS owner alias, from an Amazon-maintained list \(amazon\). This is not the user-configured AWS account alias set using the IAM console. |
| AWS.EC2.Snapshots.OutpostArn | string | The ARN of the Outpost on which the snapshot is stored. |
| AWS.EC2.Snapshots.Tags.Key | string | The key of the tag. |
| AWS.EC2.Snapshots.Tags.Value | string | The value of the tag. |
| AWS.EC2.Snapshots.StorageTier | string | The storage tier in which the snapshot is stored. |
| AWS.EC2.Snapshots.RestoreExpiryTime | date | Only for archived snapshots that are temporarily restored. Indicates the date and time when a temporarily restored snapshot will be automatically re-archived. |
| AWS.EC2.Snapshots.SseType | string | Reserved for future use. |
| AWS.EC2.SnapshotsNextPageToken | string | Next page token for pagination. |

### aws-ec2-snapshot-delete

***
Deletes the specified snapshot. Required IAM Permission: ec2:DeleteSnapshot.

#### Base Command

`aws-ec2-snapshot-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| snapshot_id | The ID of the EBS snapshot. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-snapshot-copy

***
Copies a point-in-time snapshot of an EBS volume and stores it in Amazon S3. You can copy a snapshot within the same Region, from one Region to another, or from a Region to an Outpost. Required IAM Permission: ec2:CopySnapshot.

#### Base Command

`aws-ec2-snapshot-copy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| source_snapshot_id | The ID of the EBS snapshot to copy. | Required |
| source_region | The ID of the Region that contains the snapshot to be copied. | Required |
| description | A description for the EBS snapshot. | Optional |
| destination_outpost_arn | The Amazon Resource Name (ARN) of the Outpost where the snapshot will be copied. | Optional |
| encrypted | Use this parameter to encrypt a copy of an unencrypted snapshot when encryption-by-default is not enabled. Otherwise, omit it. Possible values are: true, false. | Optional |
| kms_key_id | The identifier of the AWS KMS key to use for Amazon EBS encryption. If this parameter is not specified, your AWS managed key for Amazon EBS is used. | Optional |
| presigned_url | When you copy an encrypted source snapshot using the Amazon EC2 Query API, you must supply a pre-signed URL. | Optional |
| tag_specifications | The tags to apply to the new snapshot. The tags must be separated by a semicolon (;) and specified using the format "key=key,values=val". | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Snapshots.SnapshotId | string | The ID of the new snapshot. |
| AWS.EC2.Snapshots.Tags.Key | string | The key of the tag. |
| AWS.EC2.Snapshots.Tags.Value | string | The value of the tag. |

### aws-ec2-snapshot-completed-waiter

***
A waiter function that waits until the snapshot is complete. Required IAM Permission: ec2:DescribeSnapshots.

#### Base Command

`aws-ec2-snapshot-completed-waiter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| owner_ids | A comma-separated list of possible owners IDs. Scopes the results to snapshots with the specified owners. | Optional |
| restorable_by_user_ids | A comma-separated list of IDs of the AWS accounts that can create volumes from the snapshot. | Optional |
| snapshot_ids | A comma-separated list of snapshot IDs. | Optional |
| waiter_delay | The amount of time in seconds to wait between attempts. Default 15. Default is 15. | Optional |
| waiter_max_attempts | The maximum number of attempts to be made. Default 40. Default is 40. | Optional |

#### Context Output

There is no context output for this command.

### aws-lambda-function-get

***
Returns information about the function or the specified version, including a link to download the deployment package (valid for 10 minutes). If a version is specified, only version-specific details are returned. Required IAM Permission: lambda:GetFunction.

#### Base Command

`aws-lambda-function-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| function_name | The name of the Lambda function, version, or alias. | Required |
| qualifier | Specify a version or alias to get details about a published version of the function. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.Functions.Configuration.FunctionName | string | The name of the function. |
| AWS.Lambda.Functions.Configuration.FunctionArn | string | The function's Amazon Resource Name \(ARN\). |
| AWS.Lambda.Functions.Configuration.Runtime | string | The identifier of the function's runtime. |
| AWS.Lambda.Functions.Configuration.Role | string | The function's execution role. |
| AWS.Lambda.Functions.Configuration.Handler | string | The function that Lambda calls to begin running your function. |
| AWS.Lambda.Functions.Configuration.CodeSize | number | The size of the function's deployment package, in bytes. |
| AWS.Lambda.Functions.Configuration.Description | string | The function's description. |
| AWS.Lambda.Functions.Configuration.Timeout | number | The amount of time in seconds that Lambda allows a function to run before stopping it. |
| AWS.Lambda.Functions.Configuration.MemorySize | number | The amount of memory available to the function at runtime. |
| AWS.Lambda.Functions.Configuration.LastModified | string | The date and time that the function was last updated, in ISO-8601 format. |
| AWS.Lambda.Functions.Configuration.CodeSha256 | string | The SHA256 hash of the function's deployment package. |
| AWS.Lambda.Functions.Configuration.Version | string | The version of the Lambda function. |
| AWS.Lambda.Functions.Configuration.VpcConfig.SubnetIds | array | A list of VPC subnet IDs. |
| AWS.Lambda.Functions.Configuration.VpcConfig.SecurityGroupIds | array | A list of VPC security group IDs. |
| AWS.Lambda.Functions.Configuration.VpcConfig.VpcId | string | The ID of the VPC. |
| AWS.Lambda.Functions.Code.RepositoryType | string | The repository from which you can download the function. |
| AWS.Lambda.Functions.Code.Location | string | The presigned URL you can use to download the function's .zip file. |
| AWS.Lambda.Functions.Tags | object | The function's tags. |
| AWS.Lambda.Functions.Concurrency.ReservedConcurrentExecutions | number | The number of concurrent executions that are reserved for this function. |
| AWS.Lambda.Functions.Region | string | The AWS Region. |

### aws-lambda-functions-list

***
Returns a list of your Lambda functions. For each function, the response includes the function configuration information. Required IAM Permission: lambda:ListFunctions.

#### Base Command

`aws-lambda-functions-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| limit | Maximum number of functions to return in a single request. Valid range is 1-50. Default is 50. | Optional |
| next_token | Token for pagination. Use the value from AWS.Lambda.FunctionsNextToken to retrieve the next page of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.Functions.FunctionName | string | The name of the function. |
| AWS.Lambda.Functions.FunctionArn | string | The function's Amazon Resource Name. |
| AWS.Lambda.Functions.Runtime | string | The runtime environment for the Lambda function. |
| AWS.Lambda.Functions.Role | string | The function's execution role. |
| AWS.Lambda.Functions.Handler | string | The function Lambda calls to begin executing your function. |
| AWS.Lambda.Functions.CodeSize | number | The size of the function's deployment package in bytes. |
| AWS.Lambda.Functions.Description | string | The function's description. |
| AWS.Lambda.Functions.Timeout | number | The amount of time that Lambda allows a function to run before terminating it. |
| AWS.Lambda.Functions.MemorySize | number | The memory allocated to the function. |
| AWS.Lambda.Functions.LastModified | date | The date and time that the function was last updated, in ISO-8601 format \(YYYY-MM-DDThh:mm:ss.sTZD\). |
| AWS.Lambda.Functions.CodeSha256 | string | The SHA256 hash of the function's deployment package. |
| AWS.Lambda.Functions.Version | string | The version of the Lambda function. |
| AWS.Lambda.Functions.VpcConfig.SubnetIds | string | A list of VPC subnet IDs. |
| AWS.Lambda.Functions.VpcConfig.SecurityGroupIds | string | A list of VPC security groups IDs. |
| AWS.Lambda.Functions.VpcConfig.VpcId | string | The ID of the VPC. |
| AWS.Lambda.Functions.DeadLetterConfig.TargetArn | string | The Amazon Resource Name \(ARN\) of an Amazon SQS queue or Amazon SNS topic. |
| AWS.Lambda.Functions.Environment.Variables | string | Environment variable key-value pairs. |
| AWS.Lambda.Functions.Environment.Error.ErrorCode | string | The error code for environment variables that could not be applied. |
| AWS.Lambda.Functions.Environment.Error.Message | string | The error message for environment variables that could not be applied. |
| AWS.Lambda.Functions.KMSKeyArn | string | The KMS key used to encrypt the function's environment variables. Only returned if you've configured a customer managed CMK. |
| AWS.Lambda.Functions.TracingConfig.Mode | string | The function's AWS X-Ray tracing configuration mode. |
| AWS.Lambda.Functions.MasterArn | string | The ARN of the master function. |
| AWS.Lambda.Functions.RevisionId | string | Represents the latest updated revision of the function or alias. |
| AWS.Lambda.Functions.LayerVersions.Arn | string | The Amazon Resource Name \(ARN\) of the function layer. |
| AWS.Lambda.Functions.LayerVersions.CodeSize | string | The size of the layer archive in bytes. |
| AWS.Lambda.Functions.Region | string | The AWS Region. |
| AWS.Lambda.FunctionsNextToken | string | Token to use for pagination in subsequent requests. |

### aws-lambda-aliases-list

***
Returns a list of aliases created for a Lambda function. Required IAM Permission: lambda:ListAliases.

#### Base Command

`aws-lambda-aliases-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| function_name | The name of the Lambda function. | Required |
| function_version | Specify a function version to only list aliases that invoke that version. | Optional |
| limit | The maximum number of aliases to return (default is 50, maximum is 10000). Default is 50. | Optional |
| next_token | Specify the pagination token that was returned by a previous request to retrieve the next page of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.Aliases.AliasArn | string | Lambda function ARN that is qualified using the alias name as the suffix. |
| AWS.Lambda.Aliases.Name | string | Alias name. |
| AWS.Lambda.Aliases.FunctionVersion | string | Function version to which the alias points. |
| AWS.Lambda.Aliases.Description | string | Alias description. |
| AWS.Lambda.Aliases.RoutingConfig.AdditionalVersionWeights | string | The name of the second alias, and the percentage of traffic that is routed to it. |
| AWS.Lambda.Aliases.RevisionId | string | Represents the latest updated revision of the function or alias. |
| AWS.Lambda.AliasesNextToken | unknown | The pagination token for the next set of aliases. |

### aws-lambda-account-settings-get

***
Retrieves details about the account's limits and usage in an AWS Region. Required IAM Permission: lambda:GetAccountSettings.

#### Base Command

`aws-lambda-account-settings-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.AccountSettings.AccountLimit.TotalCodeSize | number | The amount of storage space that you can use for all deployment packages and layer archives. |
| AWS.Lambda.AccountSettings.AccountLimit.CodeSizeUnzipped | number | The maximum size of your function's code and layers when they're extracted. |
| AWS.Lambda.AccountSettings.AccountLimit.CodeSizeZipped | number | The maximum size of a deployment package when it's uploaded directly to AWS Lambda. Use Amazon S3 for larger files. |
| AWS.Lambda.AccountSettings.AccountLimit.ConcurrentExecutions | number | The maximum number of simultaneous function executions. |
| AWS.Lambda.AccountSettings.AccountLimit.UnreservedConcurrentExecutions | number | The maximum number of simultaneous function executions, minus the capacity that's reserved for individual functions with PutFunctionConcurrency. |
| AWS.Lambda.AccountSettings.AccountUsage.TotalCodeSize | number | The amount of storage space, in bytes, that's being used by deployment packages and layer archives. |
| AWS.Lambda.AccountSettings.AccountUsage.FunctionCount | number | The number of Lambda functions. |
| AWS.Lambda.AccountSettings.Region | string | The AWS Region. |
| AWS.Lambda.AccountSettings.AccountId | string | The AWS account ID. |

### aws-lambda-function-versions-list

***
Returns a list of versions, with the version-specific configuration of each. Required IAM Permission: lambda:ListVersionsByFunction.

#### Base Command

`aws-lambda-function-versions-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| function_name | The name of the Lambda function. | Required |
| next_token | Specify the pagination token that's returned by a previous request to retrieve the next page of results. | Optional |
| limit | The maximum number of versions to return. Note that the maximum limit is 50 items in each response. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.Functions.FunctionVersionsNextToken | String | The pagination token that's included if more results are available. |
| AWS.Lambda.Functions.FunctionArn | String | The function's Amazon Resource Name \(ARN\). |
| AWS.Lambda.Functions.FunctionVersions.FunctionArn | String | The function's Amazon Resource Name \(ARN\). |
| AWS.Lambda.Functions.FunctionVersions.Runtime | String | The identifier of the function's runtime. Runtime is required if the deployment package is a .zip file archive. |
| AWS.Lambda.Functions.FunctionVersions.Role | String | The function's execution role. |
| AWS.Lambda.Functions.FunctionVersions.Handler | String | The function that Lambda calls to begin running your function. |
| AWS.Lambda.Functions.FunctionVersions.CodeSize | Number | The size of the function's deployment package, in bytes. |
| AWS.Lambda.Functions.FunctionVersions.Description | String | The function's description. |
| AWS.Lambda.Functions.FunctionVersions.Timeout | Number | The amount of time in seconds that Lambda allows a function to run before stopping it. |
| AWS.Lambda.Functions.FunctionVersions.MemorySize | Number | The amount of memory available to the function at runtime. |
| AWS.Lambda.Functions.FunctionVersions.LastModified | String | The date and time that the function was last updated, in ISO-8601 format \(YYYY-MM-DDThh:mm:ss.sTZD\). |
| AWS.Lambda.Functions.FunctionVersions.CodeSha256 | String | The SHA256 hash of the function's deployment package. |
| AWS.Lambda.Functions.FunctionVersions.Version | String | The version of the Lambda function. |
| AWS.Lambda.Functions.FunctionVersions.VpcConfig.SubnetIds | String | A list of VPC subnet IDs. |
| AWS.Lambda.Functions.FunctionVersions.VpcConfig.SecurityGroupIds | String | A list of VPC security group IDs. |
| AWS.Lambda.Functions.FunctionVersions.VpcConfig.VpcId | String | The ID of the VPC. |
| AWS.Lambda.Functions.FunctionVersions.DeadLetterConfig.TargetArn | String | The Amazon Resource Name \(ARN\) of an Amazon SQS queue or Amazon SNS topic. |
| AWS.Lambda.Functions.FunctionVersions.Environment.Variables | String | Environment variable key-value pairs. Omitted from CloudTrail logs. |
| AWS.Lambda.Functions.FunctionVersions.Environment.Error.ErrorCode | String | The error code for environment variables that couldn't be applied. |
| AWS.Lambda.Functions.FunctionVersions.Environment.Error.Message | String | The error message for environment variables that couldn't be applied. |
| AWS.Lambda.Functions.FunctionVersions.KMSKeyArn | String | The ARN of the KMS key used to encrypt the function's environment variables. |
| AWS.Lambda.Functions.FunctionVersions.TracingConfig.Mode | String | The tracing mode for the Lambda function. |
| AWS.Lambda.Functions.FunctionVersions.MasterArn | String | The ARN of the main function for Lambda@Edge functions. |
| AWS.Lambda.Functions.FunctionVersions.State | String | The current state of the function. When the state is Inactive, you can reactivate the function by invoking it. |
| AWS.Lambda.Functions.FunctionVersions.StateReason | String | The reason for the function's current state. |
| AWS.Lambda.Functions.FunctionVersions.StateReasonCode | String | The reason code for the current state of the function. |
| AWS.Lambda.Functions.FunctionVersions.LastUpdateStatus | String | The status of the last update that was performed on the function. This is first set to Successful after function creation completes. |
| AWS.Lambda.Functions.FunctionVersions.LastUpdateStatusReason | String | The reason for the last update that was performed on the function. |
| AWS.Lambda.Functions.FunctionVersions.LastUpdateStatusReasonCode | String | The reason code for the last update operation status. |
| AWS.Lambda.Functions.FunctionVersions.PackageType | String | The type of deployment package. Set to Image for container image and set Zip for .zip file archive. |

### aws-lambda-function-url-config-delete

***
Deletes a Lambda function URL. When you delete a function URL, you can't recover it. Creating a new function URL results in a different URL address. Required IAM Permission: lambda:DeleteFunctionUrlConfig.

#### Base Command

`aws-lambda-function-url-config-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| function_name | The name of the Lambda function. | Required |
| qualifier | The alias name or version number. | Optional |

#### Context Output

There is no context output for this command.

### aws-lambda-function-create

***
Creates a Lambda function. To create a function, you need a deployment package and an execution role. Required IAM Permission: lambda:CreateFunction.

#### Base Command

`aws-lambda-function-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| function_name | The name of the Lambda function. | Required |
| runtime | The runtime environment for the function. | Required |
| handler | The name of the method within your code that Lambda calls to execute your function. Example: lambda_function.lambda_handler. | Required |
| role | The Amazon Resource Name (ARN) of the function's execution role. | Required |
| code | Entry ID of the uploaded base64-encoded contents of the deployment package. | Optional |
| s3_bucket | An Amazon S3 bucket in the same Amazon Web Services Region as your function. The bucket can be in a different Amazon Web Services account. | Optional |
| description | A description of the function. | Optional |
| function_timeout | The amount of time (in seconds) that Lambda allows a function to run before stopping it. Default is 3. | Optional |
| memory_size | The amount of memory (in MB) available to the function at runtime. Default is 128. | Optional |
| publish | Set to true to publish the first version of the function during creation. Possible values are: true, false. | Optional |
| subnet_ids | A comma-separated list of VPC subnet IDs. | Optional |
| security_group_ids | A comma-separated list of VPC security group IDs. | Optional |
| ipv6_allowed_for_dual_stack | Allows outbound IPv6 traffic on VPC functions that are connected to dual-stack subnets. Possible values are: true, false. | Optional |
| package_type | The type of deployment package. Possible values are: Image, Zip. | Optional |
| environment | The environment variables for the function. Must be separated by a semicolon (;) and specified using the format "key=DB_HOST,value=localhost;key=DEBUG,value=true". | Optional |
| tracing_config | The tracing configuration for the function. Set to Active to sample and trace a subset of incoming requests with X-Ray. Possible values are: Active, PassThrough. Default is Active. | Optional |
| tags | The list of tags to apply to the function. Must be separated by a semicolon (;) and specified using the format "key=abc,value=123;key=fed,value=456". | Optional |
| layers | A list of function layers to add to the function's execution environment. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.Functions.FunctionName | string | The name of the function. |
| AWS.Lambda.Functions.FunctionArn | string | The function's Amazon Resource Name \(ARN\). |
| AWS.Lambda.Functions.Runtime | string | The identifier of the function's runtime. |
| AWS.Lambda.Functions.Role | string | The function's execution role. |
| AWS.Lambda.Functions.Handler | string | The function that Lambda calls to begin running your function. |
| AWS.Lambda.Functions.CodeSize | number | The size of the function's deployment package, in bytes. |
| AWS.Lambda.Functions.Description | string | The function's description. |
| AWS.Lambda.Functions.Timeout | number | The amount of time in seconds that Lambda allows a function to run before stopping it. |
| AWS.Lambda.Functions.MemorySize | number | The amount of memory available to the function at runtime. |
| AWS.Lambda.Functions.Version | string | The version of the Lambda function. |
| AWS.Lambda.Functions.VpcConfig.SubnetIds | array | A list of VPC subnet IDs. |
| AWS.Lambda.Functions.VpcConfig.SecurityGroupIds | array | A list of VPC security group IDs. |
| AWS.Lambda.Functions.VpcConfig.VpcId | string | The ID of the VPC. |
| AWS.Lambda.Functions.VpcConfig.Ipv6AllowedForDualStack | boolean | Allows outbound IPv6 traffic on VPC functions that are connected to dual-stack subnets. |
| AWS.Lambda.Functions.PackageType | string | The type of deployment package. Set to Image for container image and set Zip for .zip file archive. |
| AWS.Lambda.Functions.LastModified | string | The date and time that the function was last updated, in ISO-8601 format. |
| AWS.Lambda.Functions.Region | string | The AWS Region. |

### aws-lambda-layer-version-list

***
Lists the versions of an Lambda layer. Required IAM Permission: lambda:ListLayerVersions.

#### Base Command

`aws-lambda-layer-version-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| layer_name | The name or Amazon Resource Name (ARN) of the layer. | Required |
| compatible_runtime | A runtime identifier. For example, java21. | Optional |
| next_token | A pagination token returned by a previous call. | Optional |
| limit | The maximum number of versions to return. Note that the maximum limit is 50 items in each response. Default is 50. | Optional |
| compatible_architecture | The compatible instruction set architecture. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.LayerVersions.VersionsNextToken | string | A pagination token returned when the response doesn't contain all versions. |
| AWS.Lambda.LayerVersions.LayerVersionArn | string | The ARN of the layer version. |
| AWS.Lambda.LayerVersions.Version | number | The version number. |
| AWS.Lambda.LayerVersions.Description | string | The description of the version. |
| AWS.Lambda.LayerVersions.CreatedDate | string | The date that the version was created, in ISO 8601 format. |
| AWS.Lambda.LayerVersions.CompatibleRuntimes | array | The layer's compatible runtimes. |
| AWS.Lambda.LayerVersions.LicenseInfo | string | The layer's open-source license. |
| AWS.Lambda.LayerVersions.CompatibleArchitectures | array | A list of compatible instruction set architectures. |

### aws-lambda-function-delete

***
Deletes a Lambda function. Required IAM Permission: lambda:DeleteFunction.

#### Base Command

`aws-lambda-function-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| function_name | The name of the Lambda function or version. | Required |
| qualifier | Specify a version to delete. You can't delete a version that an alias references. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-fleet-create

***
Launches an EC2 Fleet. Required IAM Permission: ec2:CreateFleet.

#### Base Command

`aws-ec2-fleet-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| spot_allocation_strategy | Indicates how to allocate the target capacity across the Spot pools specified by the Spot Fleet request. Possible values are: lowest-price, diversified, capacity-optimized, capacity-optimized-prioritized, price-capacity-optimized. | Optional |
| instance_interruption_behavior | The behavior when a Spot Instance is interrupted. Possible values are: hibernate, stop, terminate. | Optional |
| instance_pools_to_use_count | The number of Spot pools across which to allocate your target Spot capacity. | Optional |
| max_total_price | The maximum amount per hour for Spot Instances that you are willing to pay. | Optional |
| capacity_rebalance_replacement_strategy | The replacement strategy to use. Only available for fleets of type maintain. Possible values are: launch, launch-before-terminate. | Optional |
| capacity_rebalance_termination_delay | The amount of time (in seconds) that Amazon EC2 waits before terminating the old Spot Instance after launching a new replacement Spot Instance. | Optional |
| spot_single_instance_type | Indicates that the fleet uses a single instance type to launch all Spot Instances in the fleet. Possible values are: true, false. | Optional |
| single_availability_zone | Indicates that the fleet launches all Spot Instances into a single Availability Zone. Possible values are: true, false. | Optional |
| min_target_capacity | The minimum target capacity for Spot Instances in the fleet. If the minimum target capacity is not reached, the fleet launches no instances. | Optional |
| on_demand_allocation_strategy | The launch template override order to use to fulfill on-demand capacity. Possible values are: lowest-price, prioritized. | Optional |
| on_demand_single_instance_type | Whether the fleet uses a single instance type to launch all on-demand instances in the fleet. Possible values are: true, false. | Optional |
| on_demand_single_availability_zone | Whether the fleet launches all on-demand instances into a single Availability Zone. Possible values are: true, false. | Optional |
| on_demand_min_target_capacity | The minimum target capacity for on-demand instances in the fleet. If the minimum target capacity is not reached, the fleet launches no instances. | Optional |
| on_demand_max_total_price | The maximum amount per hour you are willing to pay for on-demand instances. | Optional |
| capacity_reservation_strategy | Whether to use unused capacity reservations to fulfill on-demand capacity. Possible values are: use-capacity-reservations-first. | Optional |
| excess_capacity_termination_policy | Whether running instances should be terminated if the total target capacity of the EC2 Fleet is decreased below the current size of the EC2 Fleet. Possible values are: no-termination, termination. | Optional |
| launch_template_id | The ID of the launch template. | Optional |
| launch_template_name | The name of the launch template. | Optional |
| launch_template_version | The version number of the launch template. Default is 1. | Optional |
| availability_zone | The Availability Zone in which to launch the instances. | Optional |
| availability_zone_id | The ID of the Availability Zone in which to launch the instances. | Optional |
| image_id | The ID of the AMI. | Optional |
| instance_type | The instance type. | Optional |
| max_price | The maximum price per unit hour that you are willing to pay for a Spot Instance. | Optional |
| placement_group_id | The ID of the placement group. | Optional |
| placement_group_name | The name of the placement group. | Optional |
| priority | The priority for the launch template override. The highest priority is launched first. | Optional |
| subnet_id | The ID of the subnet in which to launch the instances. | Optional |
| weighted_capacity | The number of units provided by the specified instance type. | Optional |
| device_name | The device name (for example, /dev/sdh or xvdh). | Optional |
| ebs_encrypted | Whether the encryption state of an EBS volume is changed when restored from a backup snapshot. Possible values are: true, false. | Optional |
| ebs_delete_on_termination | Whether the EBS volume is deleted on instance termination. Possible values are: true, false. | Optional |
| ebs_iops | The number of I/O operations per second (IOPS). | Optional |
| ebs_kms_key_id | Identifier for a user-managed CMK under which the EBS volume is encrypted. | Optional |
| ebs_snapshot_id | The ID of the snapshot. | Optional |
| ebs_volume_size | The size of the volume, in GiBs. | Optional |
| ebs_volume_type | The volume type. Possible values are: gp2, gp3, io1, io2, st1, sc1, standard. | Optional |
| ebs_throughput | The throughput for the volume, in MiB/s. This parameter is valid only for gp3 volumes. | Optional |
| block_device_mappings_no_device | Suppresses the specified device included in the block device mapping of the AMI. | Optional |
| block_device_mappings_virtual_name | The virtual device name (ephemeralN). | Optional |
| total_target_capacity | The number of units to request. | Required |
| on_demand_target_capacity | The number of on-demand units to request. | Optional |
| spot_target_capacity | The number of Spot units to request. | Optional |
| default_target_capacity_type | The default TotalTargetCapacity, which is either Spot or on-demand. Possible values are: spot, on-demand, capacity-block. | Required |
| target_capacity_unit | The unit for the target capacity. Possible values are: vcpu, memory-mib, units. | Optional |
| terminate_instances_with_expiration | Whether running instances should be terminated when the EC2 Fleet expires. Possible values are: true, false. | Optional |
| type | The request type. Possible values are: request, maintain, instant. | Optional |
| valid_from | The start date and time of the request, in UTC format (YYYY-MM-DDTHH:MM:SSZ). For example, 2024-01-15T10:30:00Z. | Optional |
| valid_until | The end date and time of the request, in UTC format (YYYY-MM-DDTHH:MM:SSZ). For example, 2024-01-15T10:30:00Z. | Optional |
| replace_unhealthy_instances | Whether the EC2 Fleet should replace unhealthy instances. Possible values are: true, false. | Optional |
| tags | The tags to apply to the resource. Format: key=&lt;key&gt;,value=&lt;value&gt;;key=&lt;key&gt;,value=&lt;value&gt;. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Fleets.FleetId | string | The ID of the EC2 Fleet. |
| AWS.EC2.Fleets.Errors.LaunchTemplateAndOverrides | string | Information about the instances that could not be launched by the fleet. |
| AWS.EC2.Fleets.Instances.LaunchTemplateAndOverrides | string | The launch templates and overrides that were used for launching the instances. The values that you specify in the Overrides replace the values in of the launch template. |

### aws-ec2-fleet-delete

***
Deletes the specified EC2 Fleet. Required IAM Permission: ec2:DeleteFleets.

#### Base Command

`aws-ec2-fleet-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| fleet_ids | A comma-separated list of EC2 Fleet IDs. | Required |
| terminate_instances | Whether to terminate instances for an EC2 Fleet if it is deleted successfully. Possible values are: true, false. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.DeletedFleets.SuccessfulFleetDeletions.CurrentFleetState | string | The current state of the EC2 Fleet. |
| AWS.EC2.DeletedFleets.SuccessfulFleetDeletions.PreviousFleetState | string | The previous state of the EC2 Fleet. |
| AWS.EC2.DeletedFleets.SuccessfulFleetDeletions.FleetId | string | The ID of the EC2 Fleet. |
| AWS.EC2.DeletedFleets.UnsuccessfulFleetDeletions.Error | string | Information about the EC2 Fleets that are not successfully deleted. |
| AWS.EC2.DeletedFleets.UnsuccessfulFleetDeletions.FleetId | string | The ID of the EC2 Fleet. |

### aws-ec2-fleets-describe

***
Describes one or more of your EC2 Fleets. Required IAM Permission: ec2:DescribeFleets.

#### Base Command

`aws-ec2-fleets-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| fleet_ids | A comma-separated list of EC2 Fleet IDs. | Optional |
| limit | The maximum number of results to return in a single call. Specify a value between 1 and 1000. | Optional |
| next_token | The token for the next set of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.FleetsNextToken | string | The token for the next set of results. |
| AWS.EC2.Fleets.ActivityStatus | string | The progress of the EC2 Fleet. If there is an error, the status is error. |
| AWS.EC2.Fleets.CreateTime | date | The creation date and time of the EC2 Fleet. |
| AWS.EC2.Fleets.FleetId | string | The ID of the EC2 Fleet. |
| AWS.EC2.Fleets.FleetState | string | The state of the EC2 Fleet. |
| AWS.EC2.Fleets.ExcessCapacityTerminationPolicy | string | Whether running instances should be terminated if the target capacity of the EC2 Fleet is decreased below the current size of the EC2 Fleet. |
| AWS.EC2.Fleets.FulfilledCapacity | number | The number of units fulfilled by this request compared to the set target capacity. |
| AWS.EC2.Fleets.FulfilledOnDemandCapacity | number | The number of units fulfilled by this request compared to the set target On-Demand capacity. |
| AWS.EC2.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification | string | Describes a launch template and overrides. |
| AWS.EC2.Fleets.TargetCapacitySpecification.TotalTargetCapacity | number | The number of units to request, filled using DefaultTargetCapacityType. |
| AWS.EC2.Fleets.TargetCapacitySpecification.OnDemandTargetCapacity | number | The number of On-Demand units to request. |
| AWS.EC2.Fleets.TargetCapacitySpecification.SpotTargetCapacity | number | The maximum number of Spot units to launch. |
| AWS.EC2.Fleets.TargetCapacitySpecification.DefaultTargetCapacityType | string | The default TotalTargetCapacity, which is either Spot or On-Demand. |
| AWS.EC2.Fleets.TerminateInstancesWithExpiration | boolean | Whether running instances should be terminated when the EC2 Fleet expires. |
| AWS.EC2.Fleets.Type | string | The type of request. Indicates whether the EC2 Fleet only requests the target capacity, or also attempts to maintain it. |
| AWS.EC2.Fleets.ValidFrom | date | The start date and time of the request, in UTC format. |
| AWS.EC2.Fleets.ValidUntil | date | The end date and time of the request, in UTC format. |
| AWS.EC2.Fleets.ReplaceUnhealthyInstances | boolean | Whether EC2 Fleet should replace unhealthy instances. |
| AWS.EC2.Fleets.SpotOptions.AllocationStrategy | string | Indicates how to allocate the target capacity across the Spot pools specified by the Spot Fleet request. |
| AWS.EC2.Fleets.SpotOptions.InstanceInterruptionBehavior | string | The behavior when a Spot Instance is interrupted. The default is terminate. |
| AWS.EC2.Fleets.SpotOptions.InstancePoolsToUseCount | number | The number of Spot pools across which to allocate your target Spot capacity. |
| AWS.EC2.Fleets.SpotOptions.SingleInstanceType | boolean | Whether the fleet uses a single instance type to launch all Spot Instances in the fleet. |
| AWS.EC2.Fleets.SpotOptions.SingleAvailabilityZone | boolean | Whether the fleet launches all Spot Instances into a single Availability Zone. |
| AWS.EC2.Fleets.SpotOptions.MinTargetCapacity | number | The minimum target capacity for Spot Instances in the fleet. |
| AWS.EC2.Fleets.OnDemandOptions.AllocationStrategy | string | The order of the launch template overrides to use in fulfilling On-Demand capacity. |
| AWS.EC2.Fleets.OnDemandOptions.SingleInstanceType | boolean | Whether the fleet uses a single instance type to launch all on-demand instances in the fleet. |
| AWS.EC2.Fleets.OnDemandOptions.SingleAvailabilityZone | boolean | Whether the fleet launches all on-demand instances into a single Availability Zone. |
| AWS.EC2.Fleets.OnDemandOptions.MinTargetCapacity | number | The minimum target capacity for on-demand instances in the fleet. |
| AWS.EC2.Fleets.Tags.Key | string | The key of the tag. |
| AWS.EC2.Fleets.Tags.Value | string | The value of the tag. |

### aws-ec2-fleet-instances-describe

***
Describes the running instances for the specified EC2 Fleet. Required IAM Permission: ec2:DescribeFleetInstances.

#### Base Command

`aws-ec2-fleet-instances-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| fleet_id | The ID of the EC2 Fleet. | Required |
| limit | The maximum number of results to return in a single call. Specify a value between 1 and 1000. | Optional |
| next_token | The token for the next set of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Fleets.ActiveInstances.InstanceId | string | The ID of the instance. |
| AWS.EC2.Fleets.ActiveInstances.InstanceType | string | The instance type. |
| AWS.EC2.Fleets.ActiveInstances.SpotInstanceRequestId | string | The ID of the Spot Instance request. |
| AWS.EC2.Fleets.ActiveInstances.InstanceHealth | string | The health status of the instance. |
| AWS.EC2.Fleets.FleetInstancesNextToken | string | The token for the next set of results. |
| AWS.EC2.Fleets.FleetId | string | The ID of the EC2 Fleet. |

### aws-ec2-fleet-modify

***
Modifies the specified EC2 Fleet. Required IAM Permission: ec2:ModifyFleet.

#### Base Command

`aws-ec2-fleet-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| fleet_id | The ID of the EC2 Fleet. | Required |
| excess_capacity_termination_policy | Whether running instances should be terminated if the total target capacity of the EC2 Fleet is decreased below the current size of the EC2 Fleet. Possible values are: no-termination, termination. | Optional |
| launch_template_id | The ID of the launch template. | Optional |
| launch_template_name | The name of the launch template. | Optional |
| launch_template_version | The version number of the launch template. Default is 1. | Optional |
| availability_zone | The Availability Zone in which to launch the instances. | Optional |
| availability_zone_id | The ID of the Availability Zone in which to launch the instances. | Optional |
| image_id | The ID of the AMI. | Optional |
| instance_type | The instance type. | Optional |
| max_price | The maximum price per unit hour that you are willing to pay for a Spot Instance. | Optional |
| placement_group_id | The ID of the placement group. | Optional |
| placement_group_name | The name of the placement group. | Optional |
| priority | The priority for the launch template override. | Optional |
| subnet_id | The ID of the subnet in which to launch the instances. | Optional |
| weighted_capacity | The number of units provided by the specified instance type. | Optional |
| device_name | The device name (for example, /dev/sdh or xvdh). | Optional |
| ebs_encrypted | Whether the encryption state of an EBS volume is changed when restored from a backup snapshot. Possible values are: true, false. | Optional |
| ebs_delete_on_termination | Whether the EBS volume is deleted on instance termination. Possible values are: true, false. | Optional |
| ebs_iops | The number of I/O operations per second (IOPS). For gp3, io1, and io2 volumes, this represents the number of IOPS that are provisioned for the volume. For gp2 volumes, this represents the baseline performance of the volume and the rate at which the volume accumulates I/O credits for bursting. This parameter is required for io1 and io2 volumes. The default for gp3 volumes is 3,000 IOPS. | Optional |
| ebs_kms_key_id | Identifier (key ID, key alias, ID ARN, or alias ARN) for a user-managed CMK under which the EBS volume is encrypted. | Optional |
| ebs_snapshot_id | The ID of the snapshot. | Optional |
| ebs_volume_size | The size of the volume, in GiBs. You must specify either an ebs_snapshot_id or an ebs_volume_size. If you specify a snapshot, the default is the snapshot size. You can specify a volume size that is equal to or larger than the snapshot size. | Optional |
| ebs_volume_type | The volume type. Possible values are: gp2, gp3, io1, io2, st1, sc1, standard. | Optional |
| ebs_throughput | The throughput for the volume, in MiB/s. This parameter is valid only for gp3 volumes. | Optional |
| block_device_mappings_no_device | Suppresses the specified device included in the block device mapping of the AMI. | Optional |
| block_device_mappings_virtual_name | The virtual device name (ephemeralN). | Optional |
| total_target_capacity | The number of units to request, filled using DefaultTargetCapacityType. | Required |
| on_demand_target_capacity | The number of On-Demand units to request. | Optional |
| spot_target_capacity | The number of Spot units to request. | Optional |
| default_target_capacity_type | The default TotalTargetCapacityType, which is either Spot or On-Demand. Possible values are: spot, on-demand, capacity-block. | Optional |
| target_capacity_unit | The unit for the target capacity. Possible values are: vcpu, memory-mib, units. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-vpc-delete

***
Deletes a specified VPC. You must detach or delete all gateways and resources that are associated with the VPC before you can delete it. Required IAM Permission: ec2:DeleteVpc.

#### Base Command

`aws-ec2-vpc-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| vpc_id | The ID of the VPC. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-vpc-endpoint-create

***
Creates a VPC endpoint for a specified service. An endpoint enables you to create a private connection between your VPC and the service. Required IAM Permission: ec2:CreateVpcEndpoint.

#### Base Command

`aws-ec2-vpc-endpoint-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| vpc_id | The VPC ID where the endpoint is created. | Required |
| service_name | The service name. For AWS services, the service name is usually in the form com.amazonaws.&lt;region&gt;.&lt;service&gt;. | Required |
| service_network_arn | The service network Amazon Resource Name (ARN) to associate with the service-network VPC endpoint. | Optional |
| service_region | The region where the service is hosted. Default is the current region. | Optional |
| vpc_endpoint_type | The type of endpoint. Possible values are: Interface, Gateway, GatewayLoadBalancer, Resource, ServiceNetwork. | Optional |
| policy_document | A policy to attach to the endpoint that controls access to the service. The policy must be in valid JSON format. | Optional |
| route_table_ids | A comma-separated list of route table IDs. Applicable for Gateway endpoints only. | Optional |
| subnet_ids | A comma-separated list of subnet IDs for an endpoint network interface. Applicable for Interface and GatewayLoadBalancer endpoints only. | Optional |
| security_group_ids | A comma-separated list of security group IDs to associate with the endpoint network interface. Applicable for Interface and GatewayLoadBalancer endpoints only. | Optional |
| ip_address_type | The IP address type for the endpoint. Possible values are: ipv4, dualstack, ipv6. | Optional |
| dns_options_dns_record_ip_type | The DNS records created for the endpoint. Possible values are: ipv4, dualstack, ipv6, service-defined. | Optional |
| dns_options_private_dns_only_for_inbound_resolver_endpoint | Whether to enable private DNS only for inbound endpoints. Possible values are: true, false. | Optional |
| dns_options_private_dns_preference | The preference for creating and associating private hosted zones with a specified VPC. | Optional |
| dns_options_private_dns_specified_domains | The private domains used for creating and associating private hosted zones with the VPC. | Optional |
| subnet_configuration_ipv4 | The IPv4 address to assign to the endpoint network interface in the subnet. | Optional |
| subnet_configuration_ipv6 | The IPv6 address to assign to the endpoint network interface in the subnet. | Optional |
| subnet_configuration_subnet_id | The ID of the subnet. | Optional |
| private_dns_enabled | Whether to associate a private hosted zone with the specified VPC. Applicable for Interface endpoints only. Possible values are: true, false. | Optional |
| resource_configuration_arn | The Amazon Resource Name (ARN) of a resource configuration that is associated with the VPC resource type endpoint. | Optional |
| tags | The tags to apply to the VPC endpoint. Format key=&lt;key&gt;,value=&lt;value&gt;;key=&lt;key&gt;,value=&lt;value&gt;. | Optional |
| client_token | Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.VpcEndpoints.VpcEndpointId | string | The ID of the VPC endpoint. |
| AWS.EC2.VpcEndpoints.VpcEndpointType | string | The type of endpoint. |
| AWS.EC2.VpcEndpoints.VpcId | string | The ID of the VPC associated with the endpoint. |
| AWS.EC2.VpcEndpoints.ServiceName | string | The name of the service associated with the endpoint. |
| AWS.EC2.VpcEndpoints.ServiceNetworkArn | string | The Amazon Resource Name \(ARN\) of the service network. |
| AWS.EC2.VpcEndpoints.ServiceRegion | string | The Region where the service is hosted. |
| AWS.EC2.VpcEndpoints.State | string | The state of the VPC endpoint. |
| AWS.EC2.VpcEndpoints.PolicyDocument | string | The policy document associated with the endpoint, if applicable. |
| AWS.EC2.VpcEndpoints.RouteTableIds | array | One or more route tables associated with the endpoint. |
| AWS.EC2.VpcEndpoints.SubnetIds | array | One or more subnets in which the endpoint is located. |
| AWS.EC2.VpcEndpoints.Groups.GroupId | string | The ID of the security group. |
| AWS.EC2.VpcEndpoints.Groups.GroupName | string | The name of the security group. |
| AWS.EC2.VpcEndpoints.IpAddressType | string | The IP address type for the endpoint. |
| AWS.EC2.VpcEndpoints.DnsOptions.DnsRecordIpType | string | The DNS records created for the endpoint. |
| AWS.EC2.VpcEndpoints.DnsOptions.PrivateDnsOnlyForInboundResolverEndpoint | boolean | Whether to enable private DNS only for inbound endpoints. |
| AWS.EC2.VpcEndpoints.DnsOptions.PrivateDnsPreference | string | The preference for which private domains have a private hosted zone created for and associated with the specified VPC. |
| AWS.EC2.VpcEndpoints.DnsOptions.PrivateDnsSpecifiedDomainSet | array | Indicates which of the private domains to create private hosted zones for and associate with the specified VPC. |
| AWS.EC2.VpcEndpoints.PrivateDnsEnabled | boolean | Whether the VPC is associated with a private hosted zone. |
| AWS.EC2.VpcEndpoints.RequesterManaged | boolean | Whether the VPC endpoint is being managed by its service. |
| AWS.EC2.VpcEndpoints.NetworkInterfaceIds | array | One or more network interfaces for the endpoint. |
| AWS.EC2.VpcEndpoints.DnsEntries.DnsName | string | The DNS name. |
| AWS.EC2.VpcEndpoints.DnsEntries.HostedZoneId | string | The ID of the private hosted zone. |
| AWS.EC2.VpcEndpoints.CreationTimestamp | date | The date and time that the VPC endpoint was created. |
| AWS.EC2.VpcEndpoints.Tags.Key | string | The key of the tag. |
| AWS.EC2.VpcEndpoints.Tags.Value | string | The value of the tag. |
| AWS.EC2.VpcEndpoints.OwnerId | string | The ID of the AWS account that owns the VPC endpoint. |
| AWS.EC2.VpcEndpoints.LastError.Message | string | The VCP endpoint error message. |
| AWS.EC2.VpcEndpoints.LastError.Code | string | The VCP endpoint error code. |
| AWS.EC2.VpcEndpoints.FailureReason | string | Reason for the failure. |
| AWS.EC2.VpcEndpoints.Ipv4Prefixes.IpPrefixes | array | Array of IPv4 prefixes. |
| AWS.EC2.VpcEndpoints.Ipv4Prefixes.SubnetId | array | ID of the subnet. |
| AWS.EC2.VpcEndpoints.Ipv6Prefixes.IpPrefixes | array | Array of IPv6 prefixes. |
| AWS.EC2.VpcEndpoints.Ipv6Prefixes.SubnetId | array | ID of the subnet. |
| AWS.EC2.VpcEndpoints.ResourceConfigurationArn | array | The Amazon Resource Name \(ARN\) of the resource configuration. |

### aws-ec2-internet-gateway-describe

***
A description of one or more of your internet gateways. Required IAM Permission: ec2:DescribeInternetGateways.

#### Base Command

`aws-ec2-internet-gateway-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for filter details and options. | Optional |
| internet_gateway_ids | A comma-separated list of internet gateway IDs. | Optional |
| limit | The maximum number of results to return with a single call. Specify a value between 5 and 1000. | Optional |
| next_token | The token for the next page of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.InternetGateways.InternetGatewayId | string | The ID of the internet gateway. |
| AWS.EC2.InternetGateways.Attachments.State | string | The current state of the attachment. |
| AWS.EC2.InternetGateways.Attachments.VpcId | string | The ID of the VPC. |
| AWS.EC2.InternetGateways.Tags.Key | string | The key of the tag. |
| AWS.EC2.InternetGateways.Tags.Value | string | The value of the tag. |
| AWS.EC2.InternetGateways.OwnerId | string | The ID of the AWS account that owns the internet gateway. |
| AWS.EC2.InternetGatewaysNextToken | string | The token used to retrieve the next page of results. |

### aws-ec2-internet-gateway-detach

***
Detaches an internet gateway from a VPC, disabling connectivity between the internet and the VPC. Required IAM Permission: ec2:DetachInternetGateway.

#### Base Command

`aws-ec2-internet-gateway-detach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| internet_gateway_id | The ID of the internet gateway. | Required |
| vpc_id | The ID of the VPC. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-internet-gateway-delete

***
Deletes the specified internet gateway. You must detach the internet gateway from the VPC before you can delete it. Required IAM Permission: ec2:DeleteInternetGateway.

#### Base Command

`aws-ec2-internet-gateway-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| internet_gateway_id | The ID of the internet gateway. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-subnet-delete

***
Deletes the specified subnet. You must terminate all running instances in the subnet before you can delete the subnet. Required IAM Permission: ec2:DeleteSubnet.

#### Base Command

`aws-ec2-subnet-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| subnet_id | The ID of the subnet. | Required |

#### Context Output

There is no context output for this command.

### aws-ec2-network-acl-entry-create

***
Creates an entry (a rule) in a network ACL with the specified rule number. Required IAM Permission: ec2:CreateNetworkAclEntry.

#### Base Command

`aws-ec2-network-acl-entry-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| network_acl_id | The ID of the network ACL. | Required |
| rule_number | The rule number for the entry (Positive integer from 1 to 32766. The range 32767 to 65535 is reserved for internal use.). ACL entries are processed in ascending order by rule number. | Required |
| protocol | The protocol number, where -1 or all specifies all protocols. Using all, -1, or any protocol other than tcp, udp, or icmp allows traffic on all ports, regardless other settings. Possible values are: tcp, udp, icmp, icmpv6, -1. | Required |
| rule_action | Whether to allow the traffic that matches the rule. Possible values are: allow, deny. | Required |
| egress | Whether it is an egress rule (a rule applied to traffic leaving the subnet). Possible values are: true, false. | Required |
| cidr_block | The IPv4 network range to allow or deny, in CIDR notation (for example, 172.16.0.0/24). You must specify either cidr_block or ipv6_cidr_block. | Optional |
| ipv6_cidr_block | The IPv6 network range to allow or deny, in CIDR notation (for example, 2001:db8:1234:1a00::/64). You must specify either cidr_block or ipv6_cidr_block. | Optional |
| icmp_type_code_type | The ICMP type. A value of -1 means all types. Required if specifying icmp or icmpv6 for the protocol parameter. | Optional |
| icmp_type_code_code | The ICMP code. A value of -1 means all codes for the specified ICMP type. Required if specifying icmp or icmpv6 for the protocol parameter. | Optional |
| port_range_from | The first port in the range. Required if specifying tcp or udp for the protocol parameter. | Optional |
| port_range_to | The last port in the range. Required if specifying tcp or udp for the protocol parameter. | Optional |

#### Context Output

There is no context output for this command.

### aws-ec2-key-pairs-describe

***
Describes the specified key pairs or all of your key pairs. Required IAM Permission: ec2:DescribeKeyPairs.

#### Base Command

`aws-ec2-key-pairs-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| key_pair_ids | A comma-separated list of key pair IDs. | Optional |
| key_names | A comma-separated list of key pair names. | Optional |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| include_public_key | If true, the public key material is included in the response. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.KeyPairs.KeyPairId | string | The ID of the key pair. |
| AWS.EC2.KeyPairs.KeyName | string | The name of the key pair. |
| AWS.EC2.KeyPairs.KeyType | string | The type of key pair \(rsa or ed25519\). |
| AWS.EC2.KeyPairs.KeyFingerprint | string | The SHA-1 digest of the DER encoded private key \(CreateKeyPair\) or MD5 public key fingerprint \(ImportKeyPair\). |
| AWS.EC2.KeyPairs.PublicKey | string | The public key material. Present only when include_public_key=true. |
| AWS.EC2.KeyPairs.CreateTime | date | The date and time the key pair was created. |
| AWS.EC2.KeyPairs.Tags | array | Any tags applied to the key pair. |

### aws-ec2-hosts-allocate

***
Allocates Dedicated Hosts to your account. Requires the instance type or family, the Availability Zone, and the quantity of hosts to allocate. Required IAM Permission: ec2:AllocateHosts.

#### Base Command

`aws-ec2-hosts-allocate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| availability_zone | The Availability Zone in which to allocate the Dedicated Host. | Required |
| availability_zone_id | The ID of the Availability Zone. | Optional |
| quantity | The number of Dedicated Hosts with these parameters to allocate to your account. | Required |
| instance_type | Specifies the instance type to be supported by the Dedicated Hosts. You cannot specify instance_type and instance_family in the same request. | Optional |
| instance_family | Specifies the instance family to be supported by the Dedicated Hosts. You cannot specify instance_type and instance_family in the same request. | Optional |
| auto_placement | Whether the host accepts untargeted instance launches matching its configuration or only accepts instance launches specifying its unique host ID. Possible values are: on, off. | Optional |
| host_recovery | Whether to enable or disable host recovery for the Dedicated Host. Host recovery is disabled by default. Possible values are: on, off. | Optional |
| host_maintenance | Whether to enable or disable host maintenance for the Dedicated Host. Possible values are: on, off. | Optional |
| outpost_arn | The Amazon Resource Name (ARN) of the Amazon Web Services Outpost on which to allocate the Dedicated Host. | Optional |
| asset_ids | A comma-separated list of IDs of the Outpost hardware assets on which to allocate the Dedicated Hosts. | Optional |
| tags | The tags to apply to the Dedicated Host during creation. Format: key=&lt;key&gt;,value=&lt;value&gt;;key=&lt;key&gt;,value=&lt;value&gt;. | Required |
| client_token | Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Hosts.HostIds | array | The IDs of the allocated Dedicated Hosts. |

### aws-ec2-hosts-release

***
Releases the specified Dedicated Hosts. Required IAM Permission: ec2:ReleaseHosts.

#### Base Command

`aws-ec2-hosts-release`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| host_ids | A comma-separated list of IDs of the Dedicated Hosts to release. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.ReleasedHosts.Successful | array | The IDs of the Dedicated Hosts that were successfully released. |
| AWS.EC2.ReleasedHosts.Unsuccessful | array | The IDs of the Dedicated Hosts that could not be released, including an error message. |

### aws-ec2-traffic-mirror-session-create

***
Creates a Traffic Mirror session. A Traffic Mirror session actively copies packets from a Traffic Mirror source to a Traffic Mirror target. Required IAM Permission: ec2:CreateTrafficMirrorSession.

#### Base Command

`aws-ec2-traffic-mirror-session-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| network_interface_id | The ID of the source network interface. | Required |
| traffic_mirror_target_id | The ID of the Traffic Mirror target. | Required |
| traffic_mirror_filter_id | The ID of the Traffic Mirror filter. | Required |
| session_number | The order in which sessions are evaluated when an interface is used by multiple sessions. Possible values are 1-32766. | Required |
| virtual_network_id | The VXLAN ID for the Traffic Mirror session. If you do not specify a virtual_network_id, an account-wide unique ID is chosen at random. | Optional |
| packet_length | The number of bytes in each packet to mirror. These are bytes after the VXLAN header. Do not specify this parameter when you want to mirror the entire packet. | Optional |
| description | The description of the Traffic Mirror session. | Optional |
| tags | The tags to assign to a Traffic Mirror session. Format: key=&lt;key&gt;,value=&lt;value&gt;;key=&lt;key&gt;,value=&lt;value&gt;. | Optional |
| client_token | Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.TrafficMirrorSessions.TrafficMirrorSessionId | string | The ID of the Traffic Mirror session. |
| AWS.EC2.TrafficMirrorSessions.TrafficMirrorTargetId | string | The ID of the Traffic Mirror target. |
| AWS.EC2.TrafficMirrorSessions.TrafficMirrorFilterId | string | The ID of the Traffic Mirror filter. |
| AWS.EC2.TrafficMirrorSessions.NetworkInterfaceId | string | The ID of the Traffic Mirror session's network interface. |
| AWS.EC2.TrafficMirrorSessions.OwnerId | string | The ID of the account that owns the Traffic Mirror session. |
| AWS.EC2.TrafficMirrorSessions.PacketLength | number | The number of bytes in each packet to mirror. |
| AWS.EC2.TrafficMirrorSessions.SessionNumber | number | The order in which sessions are evaluated when an interface is used by multiple sessions. |
| AWS.EC2.TrafficMirrorSessions.VirtualNetworkId | number | The virtual network ID associated with the Traffic Mirror session. |
| AWS.EC2.TrafficMirrorSessions.Description | string | The description of the Traffic Mirror session. |
| AWS.EC2.TrafficMirrorSessions.Tags | array | The tags assigned to the Traffic Mirror session. |

### aws-redshift-cluster-modify

***
Modifies the settings of a cluster. Requires the redshift:ModifyCluster permission. Required IAM Permission: redshift:ModifyCluster.

#### Base Command

`aws-redshift-cluster-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| cluster_identifier | The unique identifier of the cluster to be modified. | Required |
| vpc_security_group_ids | A comma-separated list of VPC security groups to be associated with the cluster. This change is asynchronously applied as soon as possible. | Optional |
| cluster_type | The new cluster type. Possible values are: multi-node, single-node. | Optional |
| node_type | The new node type of the cluster. If you specify a new node type, you must also specify the number of nodes parameter. Possible values are: dc2.large, dc2.8xlarge, ra3.large, ra3.xlplus, ra3.4xlarge, ra3.16xlarge. | Optional |
| number_of_nodes | The new number of nodes of the cluster. If you specify a new number of nodes, you must also specify the node type parameter. | Optional |
| cluster_security_groups | A comma-separated list of cluster security groups to be authorized on this cluster. | Optional |
| cluster_parameter_group_name | The name of the cluster parameter group to apply to the cluster. This change is applied only after the cluster is rebooted. Constraints: The cluster parameter group must be in the same parameter group family that matches the cluster version. | Optional |
| automated_snapshot_retention_period | The number of days that automated snapshots are retained. If the value is 0, automated snapshots are disabled. | Optional |
| manual_snapshot_retention_period | The number of days a newly created manual snapshot is retained. If the value is -1, the manual snapshot is retained indefinitely. | Optional |
| preferred_maintenance_window | The weekly time range (in UTC) during which automated cluster maintenance can occur. | Optional |
| cluster_version | The new version number of the Amazon Redshift engine to upgrade to. | Optional |
| allow_version_upgrade | Whether major version upgrades will be applied automatically to the cluster during the maintenance window. Possible values are: true, false. | Optional |
| hsm_client_certificate_identifier | The name of the HSM client certificate the Amazon Redshift cluster uses to retrieve the data encryption keys stored in an HSM. | Optional |
| hsm_configuration_identifier | The name of the HSM configuration that contains the information the Amazon Redshift cluster can use to retrieve and store keys in an HSM. | Optional |
| new_cluster_identifier | The new identifier for the cluster. | Optional |
| publicly_accessible | Whether the cluster can be accessed from a public network. Only clusters in VPCs can be set to be publicly available. Possible values are: true, false. | Optional |
| elastic_ip | The Elastic IP (EIP) address for the cluster. | Optional |
| enhanced_vpc_routing | Whether to create the cluster with enhanced VPC routing enabled. Possible values are: true, false. | Optional |
| maintenance_track_name | The name for the maintenance track that you want to assign for the cluster. This name change is asynchronous. The new track name stays in the PendingModifiedValues for the cluster until the next maintenance window. When the maintenance track changes, the cluster is switched to the latest cluster release available for the maintenance track. At this point, the maintenance track name is applied. | Optional |
| encrypted | Whether the cluster is encrypted. If the value is encrypted (true) and you provide a value for the KmsKeyId parameter, we encrypt the cluster with the provided KmsKeyId. If you don’t provide a KmsKeyId, we encrypt with the default key. If the value is not encrypted (false), then the cluster is decrypted. Possible values are: true, false. | Optional |
| kms_key_id | The Key Management Service (KMS) key ID of the encryption key that you want to use to encrypt data in the cluster. | Optional |
| availability_zone_relocation | Whether to enable relocation for an Amazon Redshift cluster between Availability Zones after the cluster modification is complete. Possible values are: true, false. | Optional |
| availability_zone | Whether to initiate relocation for an Amazon Redshift cluster to the target Availability Zone. | Optional |
| port | Whether to change the port of an Amazon Redshift cluster. | Optional |
| ip_address_type | The IP address types that the cluster supports. Possible values are: ipv4, dualstack. | Optional |
| multi_az | Whether the cluster will be modified to be deployed in two Availability Zones if the cluster is currently only deployed in a single Availability Zone. Possible values are: true, false. | Optional |
| extra_compute_for_automatic_optimization | Whether to allocate additional compute resources for running automatic optimization operations. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Redshift.Clusters.ClusterIdentifier | String | The unique identifier of the cluster. |
| AWS.Redshift.Clusters.NodeType | String | The node type for the nodes in the cluster. |
| AWS.Redshift.Clusters.ClusterStatus | String | The current state of the cluster. |
| AWS.Redshift.Clusters.ClusterAvailabilityStatus | String | The availability status of the cluster for queries. Possible values are the following: Available, Unavailable, Maintenance, Modifying, Failed. |
| AWS.Redshift.Clusters.ModifyStatus | String | The status of a cluster modification. |
| AWS.Redshift.Clusters.MasterUsername | String | The master user name for the cluster. This name is used to connect to the database that is hosted on the cluster. |
| AWS.Redshift.Clusters.DBName | String | The name of the initial database that was created when the cluster was created. |
| AWS.Redshift.Clusters.Endpoint.Address | String | The DNS address of the cluster. |
| AWS.Redshift.Clusters.Endpoint.Port | Number | The port that the database engine is listening on. |
| AWS.Redshift.Clusters.Endpoint.VpcEndpoints | Unknown | The connection endpoint description. |
| AWS.Redshift.Clusters.ClusterCreateTime | String | The date and time that the cluster was created. |
| AWS.Redshift.Clusters.AutomatedSnapshotRetentionPeriod | Number | The number of days that automatic cluster snapshots are retained. |
| AWS.Redshift.Clusters.ManualSnapshotRetentionPeriod | Number | The number of days to retain a manual snapshot. |
| AWS.Redshift.Clusters.ClusterSecurityGroups.ClusterSecurityGroupName | String | The name of a cluster security group. |
| AWS.Redshift.Clusters.ClusterSecurityGroups.Status | String | The status of the cluster security group. |
| AWS.Redshift.Clusters.VpcSecurityGroups.VpcSecurityGroupId | String | The identifier of the VPC security group. |
| AWS.Redshift.Clusters.VpcSecurityGroups.Status | String | The status of the VPC security group. |
| AWS.Redshift.Clusters.ClusterParameterGroups.ParameterGroupName | String | The name of the parameter group. |
| AWS.Redshift.Clusters.ClusterParameterGroups.ParameterApplyStatus | String | The status of parameter updates. |
| AWS.Redshift.Clusters.ClusterParameterGroups.ClusterParameterStatusList | Unknown | A comma-separated list of parameter statuses. |
| AWS.Redshift.Clusters.ClusterSubnetGroupName | String | The name of the subnet group that is associated with the cluster. |
| AWS.Redshift.Clusters.VpcId | String | The identifier of the VPC the cluster is in, if the cluster is in a VPC. |
| AWS.Redshift.Clusters.AvailabilityZone | String | The name of the Availability Zone in which the cluster is located. |
| AWS.Redshift.Clusters.PreferredMaintenanceWindow | String | The weekly time range \(in UTC\) during which system maintenance can occur. |
| AWS.Redshift.Clusters.PendingModifiedValues.MasterUserPassword | String | The pending or in-progress change of the master user password for the cluster. |
| AWS.Redshift.Clusters.PendingModifiedValues.NodeType | String | The pending or in-progress node type for the cluster. |
| AWS.Redshift.Clusters.PendingModifiedValues.NumberOfNodes | Number | The pending or in-progress number of nodes for the cluster. |
| AWS.Redshift.Clusters.PendingModifiedValues.ClusterType | String | The pending or in-progress cluster type for the cluster. |
| AWS.Redshift.Clusters.PendingModifiedValues.ClusterVersion | String | The pending or in-progress cluster version for the cluster. |
| AWS.Redshift.Clusters.PendingModifiedValues.AutomatedSnapshotRetentionPeriod | Number | The pending or in-progress change of the automated snapshot retention period for the cluster. |
| AWS.Redshift.Clusters.PendingModifiedValues.ClusterIdentifier | String | The pending or in-progress change of the new identifier for the cluster. |
| AWS.Redshift.Clusters.PendingModifiedValues.PubliclyAccessible | Boolean | The pending or in-progress change of the ability to connect to the cluster from a public network. |
| AWS.Redshift.Clusters.PendingModifiedValues.EnhancedVpcRouting | Boolean | An option that specifies whether to create the cluster with enhanced VPC routing enabled. |
| AWS.Redshift.Clusters.PendingModifiedValues.MaintenanceTrackName | String | The name of the maintenance track that the cluster will change to during the next maintenance window. |
| AWS.Redshift.Clusters.PendingModifiedValues.EncryptionType | String | The encryption type for a cluster. |
| AWS.Redshift.Clusters.ClusterVersion | String | The version ID of the Amazon Redshift engine that is running on the cluster. |
| AWS.Redshift.Clusters.AllowVersionUpgrade | Boolean | Whether major version upgrades will be applied automatically to the cluster during the maintenance window. |
| AWS.Redshift.Clusters.NumberOfNodes | Number | The number of compute nodes in the cluster. |
| AWS.Redshift.Clusters.PubliclyAccessible | Boolean | Whether the cluster can be accessed from a public network. |
| AWS.Redshift.Clusters.Encrypted | Boolean | Whether the cluster is encrypted. |
| AWS.Redshift.Clusters.RestoreStatus.Status | String | The status of the restore action. |
| AWS.Redshift.Clusters.RestoreStatus.CurrentRestoreRateInMegaBytesPerSecond | Number | The number of megabytes per second being transferred from the backup storage. |
| AWS.Redshift.Clusters.RestoreStatus.SnapshotSizeInMegaBytes | Number | The size of the set of snapshot data that was used to restore the cluster. |
| AWS.Redshift.Clusters.RestoreStatus.ProgressInMegaBytes | Number | The number of megabytes that have been transferred from snapshot storage. |
| AWS.Redshift.Clusters.RestoreStatus.ElapsedTimeInSeconds | Number | The amount of time an in-progress restore has been running, or the amount of time it took a completed restore to finish. |
| AWS.Redshift.Clusters.RestoreStatus.EstimatedTimeToCompletionInSeconds | Number | The estimate of the time remaining before the restore will complete. |
| AWS.Redshift.Clusters.DataTransferProgress.Status | String | The cluster status. |
| AWS.Redshift.Clusters.DataTransferProgress.CurrentRateInMegaBytesPerSecond | Number | The data transfer rate in megabytes per second. |
| AWS.Redshift.Clusters.DataTransferProgress.TotalDataInMegaBytes | Number | The total amount of data to be transfered in megabytes. |
| AWS.Redshift.Clusters.DataTransferProgress.DataTransferredInMegaBytes | Number | The total amount of data that has been transfered in MB’s. |
| AWS.Redshift.Clusters.DataTransferProgress.EstimatedTimeToCompletionInSeconds | Number | The estimated number of seconds remaining to complete the transfer. |
| AWS.Redshift.Clusters.DataTransferProgress.ElapsedTimeInSeconds | Number | The number of seconds that have elapsed during the data transfer. |
| AWS.Redshift.Clusters.HsmStatus.HsmClientCertificateIdentifier | String | The name of the HSM client certificate the Amazon Redshift cluster uses to retrieve the data encryption keys stored in an HSM. |
| AWS.Redshift.Clusters.HsmStatus.HsmConfigurationIdentifier | String | The name of the HSM configuration that contains the information the Amazon Redshift cluster can use to retrieve and store keys in an HSM. |
| AWS.Redshift.Clusters.HsmStatus.Status | String | Whether the Amazon Redshift cluster has finished applying any HSM settings changes specified in a modify cluster command. |
| AWS.Redshift.Clusters.ClusterSnapshotCopyStatus.DestinationRegion | String | The destination region that snapshots are automatically copied to when cross-region snapshot copy is enabled. |
| AWS.Redshift.Clusters.ClusterSnapshotCopyStatus.RetentionPeriod | Number | The number of days that automated snapshots are retained in the destination region after they are copied from a source region. |
| AWS.Redshift.Clusters.ClusterSnapshotCopyStatus.ManualSnapshotRetentionPeriod | Number | The number of days that automated snapshots are retained in the destination region after they are copied from a source region. If the value is -1, the manual snapshot is retained indefinitely. |
| AWS.Redshift.Clusters.ClusterSnapshotCopyStatus.SnapshotCopyGrantName | String | The name of the snapshot copy grant. |
| AWS.Redshift.Clusters.ClusterPublicKey | String | The public key for the cluster. |
| AWS.Redshift.Clusters.ClusterNodes.NodeRole | String | Whether the node is a leader node or a compute node. |
| AWS.Redshift.Clusters.ClusterNodes.PrivateIPAddress | String | The private IP address of a node within a cluster. |
| AWS.Redshift.Clusters.ClusterNodes.PublicIPAddress | String | The public IP address of a node within a cluster. |
| AWS.Redshift.Clusters.ElasticIpStatus.ElasticIp | String | The elastic IP \(EIP\) address for the cluster. |
| AWS.Redshift.Clusters.ElasticIpStatus.Status | String | The status of the elastic IP \(EIP\) address. |
| AWS.Redshift.Clusters.ClusterRevisionNumber | String | The specific revision number of the database in the cluster. |
| AWS.Redshift.Clusters.Tags.Key | String | The key, or name, for the resource tag. |
| AWS.Redshift.Clusters.Tags.Value | String | The value for the resource tag. |
| AWS.Redshift.Clusters.KmsKeyId | String | The Key Management Service \(KMS\) key ID of the encryption key used to encrypt data in the cluster. |
| AWS.Redshift.Clusters.EnhancedVpcRouting | Boolean | Whether to create the cluster with enhanced VPC routing enabled. |
| AWS.Redshift.Clusters.IamRoles.IamRoleArn | String | The Amazon Resource Name \(ARN\) of the IAM role. |
| AWS.Redshift.Clusters.IamRoles.ApplyStatus | String | The status of the IAM role’s association with an Amazon Redshift cluster. |
| AWS.Redshift.Clusters.PendingActions | Unknown | The cluster operations that are waiting to be started. |
| AWS.Redshift.Clusters.MaintenanceTrackName | String | The name of the maintenance track for the cluster. |
| AWS.Redshift.Clusters.ElasticResizeNumberOfNodeOptions | String | The number of nodes that you can resize the cluster to with the elastic resize method. |
| AWS.Redshift.Clusters.DeferredMaintenanceWindows.DeferMaintenanceIdentifier | String | A unique identifier for the maintenance window. |
| AWS.Redshift.Clusters.DeferredMaintenanceWindows.DeferMaintenanceStartTime | String | A timestamp for the beginning of the time period when we defer maintenance. |
| AWS.Redshift.Clusters.DeferredMaintenanceWindows.DeferMaintenanceEndTime | String | A timestamp for the end of the time period when we defer maintenance. |
| AWS.Redshift.Clusters.SnapshotScheduleIdentifier | String | A unique identifier for the cluster snapshot schedule. |
| AWS.Redshift.Clusters.SnapshotScheduleState | String | The current state of the cluster snapshot schedule. |
| AWS.Redshift.Clusters.ExpectedNextSnapshotScheduleTime | String | The current state of the cluster snapshot schedule. |
| AWS.Redshift.Clusters.ExpectedNextSnapshotScheduleTimeStatus | String | The status of next expected snapshot for clusters having a valid snapshot schedule and backups enabled. |
| AWS.Redshift.Clusters.NextMaintenanceWindowStartTime | String | The date and time in UTC when system maintenance can begin. |
| AWS.Redshift.Clusters.ResizeInfo.ResizeType | String | Returns the value ClassicResize. |
| AWS.Redshift.Clusters.ResizeInfo.AllowCancelResize | Boolean | Whether the resize operation can be cancelled. |
| AWS.Redshift.Clusters.AvailabilityZoneRelocationStatus | String | The status of the Availability Zone relocation operation. |
| AWS.Redshift.Clusters.ClusterNamespaceArn | String | The namespace Amazon Resource Name \(ARN\) of the cluster. |
| AWS.Redshift.Clusters.TotalStorageCapacityInMegaBytes | Number | The total storage capacity of the cluster in megabytes. |
| AWS.Redshift.Clusters.DefaultIamRoleArn | String | The Amazon Resource Name \(ARN\) for the IAM role set as default for the cluster. |
| AWS.Redshift.Clusters.ReservedNodeExchangeStatus.ReservedNodeExchangeRequestId | String | The identifier of the reserved-node exchange request. |
| AWS.Redshift.Clusters.ReservedNodeExchangeStatus.Status | String | The status of the reserved-node exchange request. |
| AWS.Redshift.Clusters.ReservedNodeExchangeStatus.RequestTime | String | The date and time the reserved-node exchange was requested. |
| AWS.Redshift.Clusters.ReservedNodeExchangeStatus.SourceReservedNodeId | String | The identifier of the source reserved node. |
| AWS.Redshift.Clusters.ReservedNodeExchangeStatus.SourceReservedNodeType | String | The source reserved-node type. |
| AWS.Redshift.Clusters.ReservedNodeExchangeStatus.SourceReservedNodeCount | Number | The source reserved-node count in the cluster. |
| AWS.Redshift.Clusters.ReservedNodeExchangeStatus.TargetReservedNodeOfferingId | String | The identifier of the target reserved node offering. |
| AWS.Redshift.Clusters.ReservedNodeExchangeStatus.TargetReservedNodeType | String | The node type of the target reserved node. |
| AWS.Redshift.Clusters.ReservedNodeExchangeStatus.TargetReservedNodeCount | Number | The count of target reserved nodes in the cluster. |
| AWS.Redshift.Clusters.CustomDomainName | String | The custom domain name associated with the cluster. |
| AWS.Redshift.Clusters.CustomDomainCertificateArn | String | The certificate Amazon Resource Name \(ARN\) for the custom domain name. |
| AWS.Redshift.Clusters.CustomDomainCertificateExpiryDate | String | The expiration date for the certificate associated with the custom domain name. |
| AWS.Redshift.Clusters.MasterPasswordSecretArn | String | The Amazon Resource Name \(ARN\) for the cluster’s admin user credentials secret. |
| AWS.Redshift.Clusters.MasterPasswordSecretKmsKeyId | String | The ID of the Key Management Service \(KMS\) key used to encrypt and store the cluster’s admin credentials secret. |
| AWS.Redshift.Clusters.IpAddressType | String | The IP address type for the cluster. |
| AWS.Redshift.Clusters.MultiAZ | Boolean | Whether the cluster is deployed in two Availability Zones. |
| AWS.Redshift.Clusters.MultiAZSecondary.AvailabilityZone | String | The name of the Availability Zone in which the secondary compute unit of the cluster is located. |
| AWS.Redshift.Clusters.MultiAZSecondary.ClusterNodes | String | The nodes in the secondary compute unit. |
| AWS.Redshift.Clusters.LakehouseRegistrationStatus | String | The status of the lakehouse registration for the cluster. Indicates whether the cluster is successfully registered with Amazon Redshift federated permissions. |
| AWS.Redshift.Clusters.CatalogArn | String | The Amazon Resource Name \(ARN\) of the Glue data catalog associated with the cluster enabled with Amazon Redshift federated permissions. |
| AWS.Redshift.Clusters.ExtraComputeForAutomaticOptimization | String | Whether the cluster allocates additional compute resources to run automatic optimization operations. |

### aws-rds-db-instances-describe

***
Returns information about provisioned RDS instances. Requires the rds:DescribeDBInstances permission. Required IAM Permission: rds:DescribeDBInstances.

#### Base Command

`aws-rds-db-instances-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| db_instance_identifier | The user-supplied instance identifier or the Amazon Resource Name (ARN) of the DB instance. If this parameter is specified, information from only the specific DB instance is returned. This parameter isn't case-sensitive. | Optional |
| filters | One or more filters separated by ';' (for example, name=&lt;name&gt;,values=&lt;values&gt;;name=&lt;name&gt;,values=&lt;values&gt;). See AWS documentation for details &amp; filter options. | Optional |
| limit | The maximum number of records to include in the response. If more records exist than the specified limit value, a pagination token is included in the response so that the remaining results can be retrieved. The minimum value is 20, the maximum is 100. | Optional |
| next_token | An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the token, up to the value specified by limit. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.RDS.DBInstancesNextToken | String | An optional pagination token provided by a previous request. |
| AWS.RDS.DBInstances.DBInstanceIdentifier | String | The user-supplied database identifier. This identifier is the unique key that identifies a DB instance. |
| AWS.RDS.DBInstances.DBInstanceClass | String | The name of the compute and memory capacity class of the DB instance. |
| AWS.RDS.DBInstances.Engine | String | The database engine used for this DB instance. |
| AWS.RDS.DBInstances.DBInstanceStatus | String | The current state of this database. |
| AWS.RDS.DBInstances.MasterUsername | String | The master username for the DB instance. |
| AWS.RDS.DBInstances.DBName | String | The initial database name that you provided \(if required\) when you created the DB instance. |
| AWS.RDS.DBInstances.Endpoint.Address | String | The DNS address of the DB instance. |
| AWS.RDS.DBInstances.Endpoint.Port | Number | The port that the database engine is listening on. |
| AWS.RDS.DBInstances.Endpoint.HostedZoneId | String | The ID that Amazon Route 53 assigns when you create a hosted zone. |
| AWS.RDS.DBInstances.AllocatedStorage | Number | The amount of storage in GiB allocated for the DB instance. |
| AWS.RDS.DBInstances.InstanceCreateTime | String | The date and time the DB instance was created. |
| AWS.RDS.DBInstances.PreferredBackupWindow | String | The daily time range during which automated backups are created if automated backups are enabled, as determined by the BackupRetentionPeriod. |
| AWS.RDS.DBInstances.BackupRetentionPeriod | Number | The number of days automatic DB snapshots are retained. |
| AWS.RDS.DBInstances.DBSecurityGroups.DBSecurityGroupName | String | The name of the DB security group. |
| AWS.RDS.DBInstances.DBSecurityGroups.Status | String | The status of the DB security group. |
| AWS.RDS.DBInstances.VpcSecurityGroups.VpcSecurityGroupId | String | The name of the VPC security group. |
| AWS.RDS.DBInstances.VpcSecurityGroups.Status | String | The membership status of the VPC security group. |
| AWS.RDS.DBInstances.DBParameterGroups.DBParameterGroupName | String | The name of the DB parameter group. |
| AWS.RDS.DBInstances.DBParameterGroups.ParameterApplyStatus | String | The status of parameter updates. |
| AWS.RDS.DBInstances.AvailabilityZone | String | The name of the Availability Zone where the DB instance is located. |
| AWS.RDS.DBInstances.DBSubnetGroup.DBSubnetGroupName | String | The name of the DB subnet group. |
| AWS.RDS.DBInstances.DBSubnetGroup.DBSubnetGroupDescription | String | The description of the DB subnet group. |
| AWS.RDS.DBInstances.DBSubnetGroup.VpcId | String | The VpcId of the DB subnet group. |
| AWS.RDS.DBInstances.DBSubnetGroup.SubnetGroupStatus | String | The status of the DB subnet group. |
| AWS.RDS.DBInstances.DBSubnetGroup.Subnets | Unknown | A list of Subnet elements. |
| AWS.RDS.DBInstances.DBSubnetGroup.DBSubnetGroupArn | String | The Amazon Resource Name \(ARN\) for the DB subnet group. |
| AWS.RDS.DBInstances.DBSubnetGroup.SupportedNetworkTypes | String | The network type of the DB subnet group. |
| AWS.RDS.DBInstances.PreferredMaintenanceWindow | String | The weekly time range during which system maintenance can occur, in UTC. |
| AWS.RDS.DBInstances.UpgradeRolloutOrder | String | The order in which the instances are upgraded. |
| AWS.RDS.DBInstances.PendingModifiedValues.DBInstanceClass | String | The name of the compute and memory capacity class for the DB instance. |
| AWS.RDS.DBInstances.PendingModifiedValues.AllocatedStorage | Number | The allocated storage size for the DB instance specified in gibibytes \(GiB\). |
| AWS.RDS.DBInstances.PendingModifiedValues.Port | Number | The port for the DB instance. |
| AWS.RDS.DBInstances.PendingModifiedValues.BackupRetentionPeriod | Number | The number of days automated backups are retained. |
| AWS.RDS.DBInstances.PendingModifiedValues.MultiAZ | String | Whether the Single-AZ DB instance will change to a Multi-AZ deployment. |
| AWS.RDS.DBInstances.PendingModifiedValues.EngineVersion | String | The database engine version. |
| AWS.RDS.DBInstances.PendingModifiedValues.LicenseModel | String | The license model for the DB instance. |
| AWS.RDS.DBInstances.PendingModifiedValues.Iops | Number | The Provisioned IOPS value for the DB instance. |
| AWS.RDS.DBInstances.PendingModifiedValues.StorageThroughput | Number | The storage throughput of the DB instance. |
| AWS.RDS.DBInstances.PendingModifiedValues.DBInstanceIdentifier | String | The database identifier for the DB instance. |
| AWS.RDS.DBInstances.PendingModifiedValues.StorageType | String | The storage type of the DB instance. |
| AWS.RDS.DBInstances.PendingModifiedValues.CACertificateIdentifier | String | The identifier of the CA certificate for the DB instance. |
| AWS.RDS.DBInstances.PendingModifiedValues.DBSubnetGroupName | String | The DB subnet group for the DB instance. |
| AWS.RDS.DBInstances.PendingModifiedValues.PendingCloudwatchLogsExports | Unknown | A list of log types whose configuration is still pending, they are in the process of being activated or deactivated. |
| AWS.RDS.DBInstances.PendingModifiedValues.ProcessorFeatures | Unknown | The number of CPU cores and the number of threads per core for the DB instance class of the DB instance. |
| AWS.RDS.DBInstances.PendingModifiedValues.AutomationMode | String | The automation mode of the RDS Custom DB instance: full or all-paused. |
| AWS.RDS.DBInstances.PendingModifiedValues.ResumeFullAutomationModeTime | String | The number of minutes to pause the automation. |
| AWS.RDS.DBInstances.PendingModifiedValues.MultiTenant | Boolean | Whether the DB instance will change to the multi-tenant configuration \(TRUE\) or the single-tenant configuration \(FALSE\). |
| AWS.RDS.DBInstances.PendingModifiedValues.IAMDatabaseAuthenticationEnabled | Boolean | Whether mapping of Amazon Web Services Identity and Access Management \(IAM\) accounts to database accounts is enabled. |
| AWS.RDS.DBInstances.PendingModifiedValues.DedicatedLogVolume | Boolean | Whether the DB instance has a dedicated log volume \(DLV\) enabled. |
| AWS.RDS.DBInstances.PendingModifiedValues.Engine | String | The database engine of the DB instance. |
| AWS.RDS.DBInstances.PendingModifiedValues.AdditionalStorageVolumes | Unknown | The additional storage volume modifications that are pending for the DB instance. |
| AWS.RDS.DBInstances.LatestRestorableTime | String | The latest time to which a database in this DB instance can be restored with point-in-time restore. |
| AWS.RDS.DBInstances.MultiAZ | Boolean | Whether the DB instance is a Multi-AZ deployment. This setting doesn’t apply to RDS Custom DB instances. |
| AWS.RDS.DBInstances.EngineVersion | String | The version of the database engine. |
| AWS.RDS.DBInstances.AutoMinorVersionUpgrade | Boolean | Whether minor version patches are applied automatically. |
| AWS.RDS.DBInstances.ReadReplicaSourceDBInstanceIdentifier | String | The identifier of the source DB instance if this DB instance is a read replica. |
| AWS.RDS.DBInstances.ReadReplicaDBInstanceIdentifiers | String | The identifiers of the read replicas associated with this DB instance. |
| AWS.RDS.DBInstances.ReadReplicaDBClusterIdentifiers | String | The identifiers of Aurora DB clusters to which the RDS DB instance is replicated as a read replica. |
| AWS.RDS.DBInstances.ReplicaMode | String | The open mode of a Db2 or an Oracle read replica. |
| AWS.RDS.DBInstances.LicenseModel | String | The license model information for this DB instance. |
| AWS.RDS.DBInstances.Iops | Number | The Provisioned IOPS \(I/O operations per second\) value for the DB instance. |
| AWS.RDS.DBInstances.StorageThroughput | Number | The storage throughput for the DB instance. |
| AWS.RDS.DBInstances.OptionGroupMemberships.OptionGroupName | String | The name of the option group that the instance belongs to. |
| AWS.RDS.DBInstances.OptionGroupMemberships.Status | String | The status of the DB instance’s option group membership. |
| AWS.RDS.DBInstances.CharacterSetName | String | Specifies the name of the character set that this instance is associated with. |
| AWS.RDS.DBInstances.NcharCharacterSetName | String | The name of the NCHAR character set for the Oracle DB instance. |
| AWS.RDS.DBInstances.SecondaryAvailabilityZone | String | Specifies the name of the secondary Availability Zone for a DB instance with multi-AZ support. |
| AWS.RDS.DBInstances.PubliclyAccessible | Boolean | Whether the DB instance is publicly accessible. |
| AWS.RDS.DBInstances.StatusInfos | Unknown | The status of a read replica. |
| AWS.RDS.DBInstances.StorageType | String | The storage type associated with the DB instance. |
| AWS.RDS.DBInstances.StorageEncryptionType | String | The type of encryption used to protect data at rest in the DB instance. |
| AWS.RDS.DBInstances.TdeCredentialArn | String | The ARN from the key store with which the instance is associated for TDE encryption. |
| AWS.RDS.DBInstances.DbInstancePort | Number | The port that the DB instance listens on. |
| AWS.RDS.DBInstances.DBClusterIdentifier | String | The name of the DB cluster that the DB instance is a member of \(if it is a member of a DB cluster\). |
| AWS.RDS.DBInstances.StorageEncrypted | Boolean | Whether the DB instance is encrypted. |
| AWS.RDS.DBInstances.KmsKeyId | String | If StorageEncrypted is enabled, the Amazon Web Services KMS key identifier for the encrypted DB instance. |
| AWS.RDS.DBInstances.DbiResourceId | String | The Amazon Web Services Region-unique, immutable identifier for the DB instance. |
| AWS.RDS.DBInstances.CACertificateIdentifier | String | The identifier of the CA certificate for this DB instance. |
| AWS.RDS.DBInstances.DomainMemberships.Domain | String | The identifier of the Active Directory Domain. |
| AWS.RDS.DBInstances.DomainMemberships.Status | String | The status of the Active Directory Domain membership for the DB instance or cluster. |
| AWS.RDS.DBInstances.DomainMemberships.FQDN | String | The fully qualified domain name \(FQDN\) of the Active Directory Domain. |
| AWS.RDS.DBInstances.DomainMemberships.IAMRoleName | String | The name of the IAM role used when making API calls to the Directory Service. |
| AWS.RDS.DBInstances.DomainMemberships.OU | String | The Active Directory organizational unit for the DB instance or cluster. |
| AWS.RDS.DBInstances.DomainMemberships.AuthSecretArn | String | The ARN for the Secrets Manager secret with the credentials for the user that’s a member of the domain. |
| AWS.RDS.DBInstances.DomainMemberships.DnsIps | String | The IPv4 DNS IP addresses of the primary and secondary Active Directory domain controllers. |
| AWS.RDS.DBInstances.CopyTagsToSnapshot | Boolean | Whether tags are copied from the DB instance to snapshots of the DB instance. |
| AWS.RDS.DBInstances.MonitoringInterval | Number | The interval, in seconds, for collecting Enhanced Monitoring metrics. |
| AWS.RDS.DBInstances.EnhancedMonitoringResourceArn | String | The Amazon Resource Name \(ARN\) of the Amazon CloudWatch Logs log stream that receives the Enhanced Monitoring metrics data for the DB instance. |
| AWS.RDS.DBInstances.MonitoringRoleArn | String | The ARN for the IAM role that permits RDS to send Enhanced Monitoring metrics to Amazon CloudWatch Logs. |
| AWS.RDS.DBInstances.PromotionTier | Number | The order of priority in which an Aurora Replica is promoted to the primary instance after a failure of the existing primary instance. |
| AWS.RDS.DBInstances.DBInstanceArn | String | The Amazon Resource Name \(ARN\) for the DB instance. |
| AWS.RDS.DBInstances.Timezone | String | The time zone of the DB instance. |
| AWS.RDS.DBInstances.IAMDatabaseAuthenticationEnabled | Boolean | Whether mapping of Amazon Web Services Identity and Access Management \(IAM\) accounts to database accounts is enabled for the DB instance. |
| AWS.RDS.DBInstances.DatabaseInsightsMode | String | The mode of Database Insights that is enabled for the instance. |
| AWS.RDS.DBInstances.PerformanceInsightsEnabled | Boolean | Whether Performance Insights is enabled for the DB instance. |
| AWS.RDS.DBInstances.PerformanceInsightsKMSKeyId | String | The Amazon Web Services KMS key identifier for encryption of Performance Insights data. |
| AWS.RDS.DBInstances.PerformanceInsightsRetentionPeriod | Number | The number of days to retain Performance Insights data. |
| AWS.RDS.DBInstances.EnabledCloudwatchLogsExports | Unknown | A list of log types that this DB instance is configured to export to CloudWatch Logs. |
| AWS.RDS.DBInstances.ProcessorFeatures | Unknown | The number of CPU cores and the number of threads per core for the DB instance class of the DB instance. |
| AWS.RDS.DBInstances.DeletionProtection | Boolean | Whether the DB instance has deletion protection enabled. |
| AWS.RDS.DBInstances.AssociatedRoles.RoleArn | String | The Amazon Resource Name \(ARN\) of the role. |
| AWS.RDS.DBInstances.AssociatedRoles.FeatureName | String | The name of the feature for the IAM role. |
| AWS.RDS.DBInstances.AssociatedRoles.Status | String | The status of the IAM role association. |
| AWS.RDS.DBInstances.ListenerEndpoint.Address | String | The DNS address of the DB instance listener endpoint. |
| AWS.RDS.DBInstances.ListenerEndpoint.Port | Number | The port that the database engine is listening on for the listener endpoint. |
| AWS.RDS.DBInstances.ListenerEndpoint.HostedZoneId | String | The ID of the Amazon Route 53 hosted zone that contains the listener endpoint. |
| AWS.RDS.DBInstances.MaxAllocatedStorage | Number | The upper limit to which Amazon RDS can automatically scale the storage of the DB instance. |
| AWS.RDS.DBInstances.TagList.Key | String | The key of a tag. |
| AWS.RDS.DBInstances.TagList.Value | String | The value of a tag. |
| AWS.RDS.DBInstances.AutomationMode | String | The automation mode of the DB instance. |
| AWS.RDS.DBInstances.ResumeFullAutomationModeTime | String | The time when the DB instance will resume full automation mode. |
| AWS.RDS.DBInstances.CustomerOwnedIpEnabled | Boolean | Whether the DB instance has a customer-owned IP address. |
| AWS.RDS.DBInstances.NetworkType | String | The network type of the DB instance. |
| AWS.RDS.DBInstances.ActivityStreamStatus | String | The status of the activity stream. |
| AWS.RDS.DBInstances.ActivityStreamKmsKeyId | String | The AWS KMS key identifier for encryption of the activity stream. |
| AWS.RDS.DBInstances.ActivityStreamKinesisStreamName | String | The name of the Amazon Kinesis data stream used for the activity stream. |
| AWS.RDS.DBInstances.ActivityStreamMode | String | The mode of the activity stream. |
| AWS.RDS.DBInstances.ActivityStreamEngineNativeAuditFieldsIncluded | Boolean | Whether the native audit fields are included in the activity stream. |
| AWS.RDS.DBInstances.AwsBackupRecoveryPointArn | String | The Amazon Resource Name \(ARN\) of the recovery point in AWS Backup. |
| AWS.RDS.DBInstances.DBInstanceAutomatedBackupsReplications.DBInstanceAutomatedBackupsArn | String | The Amazon Resource Name \(ARN\) of the replicated automated backups. |
| AWS.RDS.DBInstances.BackupTarget | String | The backup target of the DB instance. |
| AWS.RDS.DBInstances.AutomaticRestartTime | String | The time the DB instance is scheduled for automatic restart. |
| AWS.RDS.DBInstances.CustomIamInstanceProfile | String | The instance profile associated with the DB instance. |
| AWS.RDS.DBInstances.ActivityStreamPolicyStatus | String | The status of the policy used for the activity stream. |
| AWS.RDS.DBInstances.CertificateDetails.CAIdentifier | String | The CA identifier of the certificate. |
| AWS.RDS.DBInstances.CertificateDetails.ValidTill | String | The expiration date of the certificate. |
| AWS.RDS.DBInstances.DBSystemId | String | The DB system identifier of the DB instance. |
| AWS.RDS.DBInstances.MasterUserSecret.SecretArn | String | The Amazon Resource Name \(ARN\) of the secret. |
| AWS.RDS.DBInstances.MasterUserSecret.SecretStatus | String | The status of the secret. |
| AWS.RDS.DBInstances.MasterUserSecret.KmsKeyId | String | The AWS KMS key identifier that is used to encrypt the secret. |
| AWS.RDS.DBInstances.ReadReplicaSourceDBClusterIdentifier | String | The identifier of the source DB cluster if this DB instance is a read replica. |
| AWS.RDS.DBInstances.PercentProgress | String | The percentage of the estimated data that has been transferred. |
| AWS.RDS.DBInstances.MultiTenant | Boolean | Whether the DB instance is a multi-tenant instance. |
| AWS.RDS.DBInstances.DedicatedLogVolume | Boolean | Whether the DB instance has a dedicated log volume. |
| AWS.RDS.DBInstances.IsStorageConfigUpgradeAvailable | Boolean | Whether a storage configuration upgrade is available for the DB instance. |
| AWS.RDS.DBInstances.EngineLifecycleSupport | String | The life cycle of the DB instance engine. |
| AWS.RDS.DBInstances.AdditionalStorageVolumes.VolumeName | String | The name of the storage volume. |
| AWS.RDS.DBInstances.AdditionalStorageVolumes.StorageVolumeStatus | String | The status of the storage volume. |
| AWS.RDS.DBInstances.AdditionalStorageVolumes.AllocatedStorage | Number | The allocated storage for the storage volume. |
| AWS.RDS.DBInstances.AdditionalStorageVolumes.IOPS | Number | The IOPS for the storage volume. |
| AWS.RDS.DBInstances.AdditionalStorageVolumes.MaxAllocatedStorage | Number | The maximum allocated storage for the storage volume. |
| AWS.RDS.DBInstances.AdditionalStorageVolumes.StorageThroughput | Number | The storage throughput for the storage volume. |
| AWS.RDS.DBInstances.AdditionalStorageVolumes.StorageType | String | The storage type for the storage volume. |
| AWS.RDS.DBInstances.StorageVolumeStatus | String | The detailed status information for storage volumes associated with the DB instance. |

### aws-lambda-function-configuration-update

***
Updates the configuration for a Lambda function. Requires the lambda:UpdateFunctionConfiguration permission. Required IAM Permission: lambda:UpdateFunctionConfiguration.

#### Base Command

`aws-lambda-function-configuration-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required |
| region | The AWS region. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, af-south-1, ap-east-1, ap-south-2, ap-southeast-3, ap-southeast-5, ap-southeast-4, ap-south-1, ap-northeast-3, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-southeast-7, ap-northeast-1, ca-central-1, ca-west-1, eu-central-1, eu-west-1, eu-west-2, eu-south-1, eu-west-3, eu-south-2, eu-north-1, eu-central-2, il-central-1, mx-central-1, me-south-1, me-central-1, sa-east-1, us-gov-east-1, us-gov-west-1. | Required |
| function_name | The name or ARN of the Lambda function. | Required |
| role | The Amazon Resource Name (ARN) of the function's execution role. | Optional |
| handler | The name of the method within your code that Lambda calls to execute your function. | Optional |
| description | A description of the function. | Optional |
| timeout | The amount of time that Lambda allows a function to run before stopping it. Default is 3. | Optional |
| memory_size | The amount of memory, in MB, that your function has access to. Default is 128. | Optional |
| subnet_ids | A comma-separated list of VPC subnet IDs. | Optional |
| security_group_ids | A comma-separated list of VPC security group IDs. | Optional |
| ipv6_allowed_for_dualstack | Allows outbound IPv6 traffic on VPC functions that are connected to dual-stack subnets. Possible values are: true, false. | Optional |
| environment | Environment variable key-value pairs. Must be separated by a semicolon (;) and specified using the format "key=DB_HOST,value=localhost;key=DEBUG,value=true". | Optional |
| runtime | The identifier of the function's runtime. | Optional |
| target_arn | The Amazon Resource Name (ARN) of an Amazon SQS queue or Amazon SNS topic for the dead-letter queue configuration. | Optional |
| kms_key_arn | The ARN of the AWS Key Management Service (KMS) key to use for encryption. | Optional |
| tracing_config_mode | The tracing mode. Set Mode to Active to sample and trace a subset of incoming requests with X-Ray. Possible values are: Active, PassThrough. | Optional |
| revision_id | A revision ID to update the function only if it matches. | Optional |
| layers | A comma-separated list of function layers ARNs. | Optional |
| file_system_configs | An key-value pairs string for EFS file system configurations where the key is the Arn and the value is LocalMountPath. Arn is the Amazon Resource Name (ARN) of the Amazon EFS access point that provides access to the file system. The LocalMountPath is the path where the function can access the file system, starting with /mnt/. Must be separated by a semicolon (;) and specified using the format "key=DB_HOST,value=localhost;key=DEBUG,value=true". | Optional |
| image_config_entry_point | A comma-separated list that specifies the entry point to their application, which is typically the location of the runtime executable. | Optional |
| image_config_command | Parameters that you want to pass in with ENTRYPOINT. | Optional |
| image_config_working_directory | Specifies the working directory. | Optional |
| ephemeral_storage_size | The size of the function’s /tmp directory. | Optional |
| snap_start_apply_on | Set to PublishedVersions to create a snapshot of the initialized execution environment when you publish a function version. Possible values are: PublishedVersions, None. | Optional |
| log_format | The format in which Lambda sends your function’s application and system logs to CloudWatch. Possible values are: JSON, Text. | Optional |
| application_log_level | Set this property to filter the application logs for your function that Lambda sends to CloudWatch. Possible values are: TRACE, DEBUG, INFO, WARN, ERROR, FATAL. | Optional |
| system_log_level | Set this property to filter the system logs for your function that Lambda sends to CloudWatch. Possible values are: DEBUG, INFO, WARN. | Optional |
| log_group | The name of the Amazon CloudWatch log group the function sends logs to. By default, Lambda functions send logs to a default log group named /aws/lambda/&lt;function name&gt;. To use a different log group, enter an existing log group or enter a new log group name. | Optional |
| capacity_provider_arn | The Amazon Resource Name (ARN) of the capacity provider. | Optional |
| per_execution_env_max_concurrency | The maximum number of concurrent execution environments that can run on each compute instance. | Optional |
| execution_env_memory_per_cpu | The amount of memory in GiB allocated per vCPU for execution environments. | Optional |
| durable_retention_period | The number of days to retain execution history after a durable execution completes. After this period, execution history is no longer available through the GetDurableExecutionHistory API. For example, enter '4' for 4 days. | Optional |
| durable_execution_timeout | The maximum time (in seconds) that a durable execution can run before timing out. This timeout applies to the entire durable execution, not individual function invocations. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.FunctionConfig.FunctionName | String | The name of the function. |
| AWS.Lambda.FunctionConfig.FunctionArn | String | The function's Amazon Resource Name \(ARN\). |
| AWS.Lambda.FunctionConfig.Runtime | String | The identifier of the function's runtime. |
| AWS.Lambda.FunctionConfig.Role | String | The function's execution role. |
| AWS.Lambda.FunctionConfig.Handler | String | The function that Lambda calls to begin running your function. |
| AWS.Lambda.FunctionConfig.CodeSize | Number | The size of the function's deployment package, in bytes. |
| AWS.Lambda.FunctionConfig.Description | String | The function's description. |
| AWS.Lambda.FunctionConfig.Timeout | Number | The amount of time in seconds that Lambda allows a function to run before stopping it. |
| AWS.Lambda.FunctionConfig.MemorySize | Number | The amount of memory available to the function at runtime. |
| AWS.Lambda.FunctionConfig.LastModified | String | The date and time the function was last updated. |
| AWS.Lambda.FunctionConfig.CodeSha256 | String | The SHA256 hash of the function's deployment package. |
| AWS.Lambda.FunctionConfig.Version | String | The version of the Lambda function. |
| AWS.Lambda.FunctionConfig.VpcConfig | Unknown | The function's networking configuration. |
| AWS.Lambda.FunctionConfig.DeadLetterConfig | Unknown | The function's dead-letter queue. |
| AWS.Lambda.FunctionConfig.Environment | String | The function's environment variables. |
| AWS.Lambda.FunctionConfig.KMSKeyArn | String | The KMS key used to encrypt the function's environment variables. |
| AWS.Lambda.FunctionConfig.TracingConfig | Unknown | The function's X-Ray tracing configuration. |
| AWS.Lambda.FunctionConfig.MasterArn | String | For Lambda@Edge functions, the ARN of the main function. |
| AWS.Lambda.FunctionConfig.RevisionId | String | The latest updated revision of the function or alias. |
| AWS.Lambda.FunctionConfig.Layers | Unknown | The function's layers. |
| AWS.Lambda.FunctionConfig.State | String | The current state of the function. |
| AWS.Lambda.FunctionConfig.StateReason | String | The reason for the function's current state. |
| AWS.Lambda.FunctionConfig.StateReasonCode | String | The reason code for the function's current state. |
| AWS.Lambda.FunctionConfig.LastUpdateStatus | String | The status of the last update that was performed on the function. |
| AWS.Lambda.FunctionConfig.LastUpdateStatusReason | String | The reason for the last update that was performed on the function. |
| AWS.Lambda.FunctionConfig.LastUpdateStatusReasonCode | String | The reason code for the last update that was performed on the function. |
| AWS.Lambda.FunctionConfig.FileSystemConfigs | Unknown | The function's Amazon EFS file system configurations. |
| AWS.Lambda.FunctionConfig.PackageType | String | The type of deployment package. |
| AWS.Lambda.FunctionConfig.ImageConfigResponse | Unknown | The function's image configuration values. |
| AWS.Lambda.FunctionConfig.SigningProfileVersionArn | String | The ARN of the signing profile version. |
| AWS.Lambda.FunctionConfig.SigningJobArn | String | The ARN of the signing job. |
| AWS.Lambda.FunctionConfig.Architectures | Unknown | The instruction set architecture that the function supports. |
| AWS.Lambda.FunctionConfig.EphemeralStorage | Number | The size of the function's /tmp directory. |
| AWS.Lambda.FunctionConfig.SnapStart | String | The function's SnapStart setting. |
| AWS.Lambda.FunctionConfig.RuntimeVersionConfig | Unknown | The ARN of the runtime and any errors that occurred. |
| AWS.Lambda.FunctionConfig.LoggingConfig | Unknown | The function's logging configuration. |
| AWS.Lambda.FunctionConfig.CapacityProviderConfig | Unknown | The configuration for Lambda-managed instances used by the capacity provider. |
| AWS.Lambda.FunctionConfig.ConfigSha256 | String | The SHA256 hash of the function configuration. |
| AWS.Lambda.FunctionConfig.DurableConfig | Unknown | The function’s durable execution configuration settings, if the function is configured for durability. |
| AWS.Lambda.FunctionConfig.TenancyConfig | Unknown | The function’s tenant isolation configuration settings. Determines whether the Lambda function runs on a shared or dedicated infrastructure per unique tenant. |
