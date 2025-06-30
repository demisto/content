# AWS Integration

This integration can be used to connect to your AWS accounts. You can run playbooks, scripts and commands on several AWS accounts using single EC2 machine. To leverage this integration with AWS, several steps must be completed to properly set up the environment within your AWS account.

***Important:*** This integration currently supports only single engine deployments. Please select appropriate engine under *Run on* section while creating the Integration instance.

## Prerequisites

- An EC2 machine with Cortex engine setup. Please refer to [What is an engine](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.6/Cortex-XSOAR-On-prem-Documentation/What-is-an-engine) and [Install an engine](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.6/Cortex-XSOAR-On-prem-Documentation/Install-an-engine) for more details on Cortex engine.
- EC2 instance should have `sts:AssumeRole` permission over target AWS roles used for accessing your AWS accounts.
- Target AWS roles should have appropriate permissions to perform required action on the AWS account.

For detailed instructions, see the [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

## Authentication Mechanism

- This integration utilizes the IAM role assigned to the AWS EC2 instance via an instance profile to assume target roles for performing the necessary actions. Therefore, the EC2 instance must have the `sts:AssumeRole` permission for the target AWS roles.

- Target roles are identified based on a combination of the `Role Name` specified during integration setup and the `account_id` provided as an argument in the integration commands. For example: `arn:aws:iam::<account_id>:role/<aws_role_name>`.

- Target roles may exist across different AWS accounts. To enable the EC2 instance to assume these roles, you must configure appropriate permissions and trust relationships.

- Target roles for all AWS accounts should have same name. This name can be configured by `Role Name` integration input.

- Target role should have appropriate permissions to perform required action on the corresponding AWS account.

- Credentials after assuming target role are utilized for performing the required action on the AWS account.

## Required Permissions 

### AWS EC2

EC2 instance should have `sts:AssumeRole` permission over target AWS roles.

### Target Role

| Command | Required Permissions |
| ------------- | ------------- |
| aws-rds-db-cluster-modify | rds:ModifyDBCluster |
| aws-rds-db-cluster-snapshot-attribute-modify | rds:ModifyDBClusterSnapshotAttribute |
| aws-rds-db-instance-modify | rds:ModifyDBInstance |
| aws-rds-db-snapshot-attribute-modify | rds:ModifyDBSnapshotAttribute |
| aws-s3-bucket-acl-put | s3:PutBucketAcl |
| aws-s3-bucket-logging-put | s3:PutBucketLogging |
| aws-s3-bucket-versioning-put | s3:PutBucketVersioning |
| aws-s3-bucket-policy-put | s3:PutBucketPolicy |
| aws-s3-public-access-block-update | s3:GetBucketPublicAccessBlock <br> s3:PutBucketPublicAccessBlock |
| aws-ec2-security-group-egress-revoke | ec2:RevokeSecurityGroupEgress |
| aws-ec2-image-attribute-modify | ec2:ModifyImageAttribute |
| aws-ec2-instance-attribute-modify | ec2:ModifyInstanceAttribute |
| aws-ec2-instance-metadata-options-modify | ec2:ModifyInstanceMetadataOptions |
| aws-ec2-snapshot-attribute-modify | ec2:ModifySnapshotAttribute |
| aws-ec2-security-group-ingress-revoke | ec2:RevokeSecurityGroupIngress |
| aws-ec2-security-group-ingress-authorize | ec2:AuthorizeSecurityGroupIngress |
| aws-eks-cluster-config-update | eks:UpdateClusterConfig |
| aws-cloudtrail-trail-update | cloudtrail:UpdateTrail |
| aws-cloudtrail-logging-start | cloudtrail:StartLogging |
| aws-iam-login-profile-delete | iam:DeleteLoginProfile |
| aws-iam-user-policy-put | iam:PutUserPolicy |
| aws-iam-role-from-instance-profile-remove | iam:RemoveRoleFromInstanceProfile |
| aws-iam-access-key-update | iam:UpdateAccessKey |
| aws-iam-account-password-policy-get | iam:GetAccountPasswordPolicy |
| aws-iam-account-password-policy-update | iam:UpdateAccountPasswordPolicy |
