Before you can use AWS Secrets Manager you need to perform several configuration steps in your AWS environment.

### Prerequisites
- Attach an instance profile with the required permissions to the Cortex XSOAR server or engine that is running 
on your AWS environment.
- The instance profile requires the following minimum permission: sts:AssumeRole.
- The instance profile requires permission to assume the roles needed by the AWS integrations.

### Configure AWS Settings
- Create an IAM role for the instance profile.
- Attach a role to the instance profile.
- Configure the necessary IAM roles that the AWS integration can assume.

For detailed instructions, see the [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).
