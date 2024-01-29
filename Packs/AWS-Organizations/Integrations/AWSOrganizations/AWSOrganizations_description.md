Before using AWS Organizations, you need to perform several configuration steps in your AWS environment.

### Prerequisites
- Attach an instance profile with the required permissions to the Cortex XSOAR server or engine that is running 
on your AWS environment.
- The instance profile requires the following minimum permission: sts:AssumeRole.
- The instance profile requires permission to assume the roles needed by the AWS integrations.

### Configure AWS Settings
1. Create an IAM role for the instance profile.
2. Attach a role to the instance profile.
3. Configure the necessary IAM roles that the AWS integration can assume.

For detailed instructions, see [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

For AWS Organizations quotas, guidelines and restrictions, see [AWS Organizations Quotas](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html).