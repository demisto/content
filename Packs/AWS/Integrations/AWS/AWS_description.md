# AWS Integration

This integration enforces AWS security best practices across your cloud environment by:
- Securing RDS instances and clusters by modifying configurations and snapshot attributes.
- Implementing S3 bucket security controls including ACLs, logging, versioning, and public access restrictions.
- Managing EC2 security groups, instance attributes, and metadata options.
- Configuring EKS cluster security settings and CloudTrail logging.
- Managing IAM policies, login profiles, and access keys.

## Supported Platforms

| Platform | Authentication |
| --- | --- |
| **Cortex Cloud (platform)** | Automatic — credentials are provided by the Cortex Cloud connector (CTS). No access keys required. |
| **Cortex XSOAR** | Manual — configure an AWS Access Key and Secret Key on the integration instance. Optionally assume a role via STS. |
| **Cortex XSIAM** | Manual — configure an AWS Access Key and Secret Key on the integration instance. Optionally assume a role via STS. |

## Multi-Account Support

When **Role name for cross-organization account access** and **AWS organization accounts** are both configured, commands are executed in parallel across every listed account. Each account result is tagged with its `AccountId`. Per-account failures do not abort the batch. This feature was previously available only in the legacy **AWS-EC2** integration and is now available for all AWS services in this unified integration.

## Configuration (XSOAR / XSIAM)

1. Create an IAM user (or use an existing one) with the required permissions listed below.
2. Generate an **Access Key ID** and **Secret Access Key** for that user.
3. On the integration instance, enter the Access Key as the username and the Secret Key as the password in the **Access Key / Secret Key** field.
4. *(Optional)* If you want the integration to assume a role, enter the full role ARN in **Role ARN**. The IAM user must have `sts:AssumeRole` permission on that role.
5. *(Optional)* For cross-account fan-out, enter a comma-separated list of account IDs in **AWS organization accounts** and the role name (that exists in each account) in **Role name for cross-organization account access**.

## Configuration (Cortex Cloud)

Cloud integrations are installed from the **Data Sources** page. Go to **Settings > Data Sources**, click **Add Data Source**, select **AWS**, then in **Advanced Settings > Security Capabilities**, enable **Automation**. No access keys are required.

## Prerequisites

For Cortex Cloud, the connector account must be granted the permissions described in:
https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Premium-Documentation/Cloud-service-provider-permissions#:~:text=Microsoft%20Azure-,Amazon%20Web%20Services%20provider%20permissions,-ADS

For XSOAR / XSIAM, the IAM user or assumed role must have the permissions listed below.

| Command | Required Permissions |
| --- | --- |
| aws-rds-db-cluster-modify | rds:ModifyDBCluster |
| aws-rds-db-cluster-snapshot-attribute-modify | rds:ModifyDBClusterSnapshotAttribute |
| aws-rds-db-instance-modify | rds:ModifyDBInstance |
| aws-rds-db-snapshot-attribute-modify | rds:ModifyDBSnapshotAttribute |
| aws-s3-bucket-acl-put | s3:PutBucketAcl |
| aws-s3-bucket-logging-put | s3:PutBucketLogging |
| aws-s3-bucket-versioning-put | s3:PutBucketVersioning |
| aws-s3-bucket-policy-put | s3:PutBucketPolicy |
| aws-s3-public-access-block-put | s3:GetBucketPublicAccessBlock, s3:PutBucketPublicAccessBlock |
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
