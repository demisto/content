# AWS Cloud Automations Integration

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
| aws-s3-public-access-block-update  | s3:PutBucketPublicAccessBlock  |
| aws-iam-account-password-policy-get  | iam:GetAccountPasswordPolicy  |
| aws-iam-account-password-policy-update  | iam:GetAccountPasswordPolicy <br> iam:UpdateAccountPasswordPolicy  |
| aws-ec2-instance-metadata-options-modify  | s3:PutBucketPublicAccessBlock  |
