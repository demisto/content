# AWS Integration

This integration enforces AWS security best practices by:
- Securing RDS instances and clusters by modifying configurations and snapshot attributes.
- Implementing S3 bucket security controls including ACLs, logging, versioning, and public access restrictions.
- Managing EC2 security groups, instance attributes, and metadata options.
- Configuring EKS cluster security settings and CloudTrail logging.
- Managing IAM policies, login profiles, and access keys.


## Prerequisites

A connect AWS account / AWS  has to be granted the permissions described in: 
https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Premium-Documentation/Cloud-service-provider-permissions#:~:text=Microsoft%20Azure-,Amazon%20Web%20Services%20provider%20permissions,-ADS


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
